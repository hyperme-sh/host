package trustedmeter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// EngineFiles must refer to immutable files inside the measured guest, not
// provider mounts. The GGUF CPU profile embeds its tokenizer in the model.
type EngineFiles struct{ Binary, Model, Template *os.File }

func verifyFile(f *os.File, digest string) error {
	if f == nil || !digestPattern.MatchString(digest) {
		return ErrInvalid
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrInvalid
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, io.NewSectionReader(f, 0, info.Size())); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrInvalid
	}
	return nil
}
func (files EngineFiles) Verify(b Binding) error {
	if b.Validate() != nil || b.ModelSHA256 != b.TokenizerSHA256 {
		return ErrInvalid
	}
	for _, entry := range []struct {
		file *os.File
		hash string
	}{{files.Binary, b.RuntimeSHA256}, {files.Model, b.ModelSHA256}, {files.Template, b.TemplateSHA256}} {
		if err := verifyFile(entry.file, entry.hash); err != nil {
			return err
		}
	}
	return nil
}

// RunCPU consumes only the private pipe of the measured engine. Output is
// released after its cumulative count is durable and anchored. This function
// must run inside the guest; file hashing alone does not establish that trust.
func RunCPU(ctx context.Context, c *Controller, files EngineFiles, request []byte, output io.Writer) (err error) {
	defer func() {
		if err != nil {
			c.Dispute()
		}
	}()
	if len(request) == 0 || len(request) > 65536 || !json.Valid(request) || output == nil {
		return ErrInvalid
	}
	if err = files.Verify(c.binding); err != nil {
		return err
	}
	// Compact to one line; the inference body is transient and never journaled.
	var value any
	if err = json.Unmarshal(request, &value); err != nil {
		return err
	}
	request, err = json.Marshal(value)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "/proc/self/fd/4", "/proc/self/fd/5")
	cmd.ExtraFiles = []*os.File{files.Binary, files.Model, files.Template}
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return err
	}
	if err = c.Start(ctx); err != nil {
		input.Close()
		stdout.Close()
		return err
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		stdout.Close()
		return err
	}
	waited := false
	defer func() {
		input.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if _, err = input.Write(append(request, '\n')); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 40000)
	completed := false
	outputReady := false
	for scanner.Scan() {
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(scanner.Bytes(), &fields); err != nil {
			return err
		}
		var event string
		if err = json.Unmarshal(fields["event"], &event); err != nil {
			return err
		}
		switch event {
		case "permit":
			if len(fields) != 3 {
				return ErrInvalid
			}
			var kind string
			var count int64
			if json.Unmarshal(fields["kind"], &kind) != nil || json.Unmarshal(fields["count"], &count) != nil {
				return ErrInvalid
			}
			outputReady = false
			if err = c.Permit(kind, count); err != nil {
				return err
			}
			if _, err = io.WriteString(input, "{\"permit\":true}\n"); err != nil {
				return err
			}
		case "counts":
			if len(fields) != 6 {
				return ErrInvalid
			}
			delete(fields, "event")
			raw, _ := json.Marshal(fields)
			var counts Counters
			if err = strict(raw, &counts); err != nil {
				return err
			}
			c.mu.Lock()
			before, hiddenBefore := c.counts.AcceptedOutput, c.counts.HiddenOutput
			c.mu.Unlock()
			if err = c.Count(ctx, counts); err != nil {
				return err
			}
			outputReady = counts.AcceptedOutput == before+1 && counts.HiddenOutput == hiddenBefore
		case "decoded":
			if len(fields) != 1 {
				return ErrInvalid
			}
			if err = c.Decoded(); err != nil {
				return err
			}
		case "output":
			if !outputReady || len(fields) != 2 {
				return ErrInvalid
			}
			var encoded string
			if json.Unmarshal(fields["hex"], &encoded) != nil {
				return ErrInvalid
			}
			text, e := hex.DecodeString(encoded)
			if e != nil || len(text) > 16384 {
				return ErrInvalid
			}
			if _, err = output.Write(text); err != nil {
				return err
			}
			outputReady = false
		case "completed":
			if len(fields) != 1 || completed {
				return ErrInvalid
			}
			completed = true
		default:
			return ErrInvalid
		}
		if completed {
			break
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	if !completed {
		return ErrDisputed
	}
	// No further events may follow a terminal marker.
	if scanner.Scan() {
		return ErrInvalid
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	input.Close()
	err = cmd.Wait()
	waited = true
	if err != nil {
		return fmt.Errorf("%w: engine exit", ErrDisputed)
	}
	return c.Finish(ctx, "completed")
}
