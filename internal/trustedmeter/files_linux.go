package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// SealFile copies untrusted storage into private guest memory, verifies the
// copied bytes, then seals all writes and size changes before any execution.
// The source may change during copying; only the expected final digest passes.
func SealFile(source *os.File, expected string, maxBytes int64) (*os.File, error) {
	if source == nil || !digestPattern.MatchString(expected) || maxBytes < 1 || maxBytes > 8<<30 {
		return nil, ErrInvalid
	}
	fd, err := unix.MemfdCreate("hypermesh-meter", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		return nil, err
	}
	target := os.NewFile(uintptr(fd), "private-meter-file")
	failed := true
	defer func() {
		if failed {
			target.Close()
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(target, hash), io.NewSectionReader(source, 0, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if n < 1 || n > maxBytes || hex.EncodeToString(hash.Sum(nil)) != expected {
		return nil, ErrInvalid
	}
	if err = target.Chmod(0555); err != nil {
		return nil, err
	}
	if _, err = unix.FcntlInt(target.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	if _, err = target.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	failed = false
	return target, nil
}
func SealedFiles(source EngineFiles, b Binding) (EngineFiles, error) {
	if b.Validate() != nil || b.TokenizerSHA256 != b.ModelSHA256 {
		return EngineFiles{}, ErrInvalid
	}
	var out EngineFiles
	entries := []struct {
		src   *os.File
		hash  string
		limit int64
		dest  **os.File
	}{
		{source.Binary, b.RuntimeSHA256, 128 << 20, &out.Binary},
		{source.Model, b.ModelSHA256, 8 << 30, &out.Model},
		{source.Template, b.TemplateSHA256, 16384, &out.Template},
	}
	for _, entry := range entries {
		f, err := SealFile(entry.src, entry.hash, entry.limit)
		if err != nil {
			out.Close()
			return EngineFiles{}, err
		}
		*entry.dest = f
	}
	return out, nil
}
func (f EngineFiles) Close() {
	for _, file := range []*os.File{f.Binary, f.Model, f.Template} {
		if file != nil {
			file.Close()
		}
	}
}
