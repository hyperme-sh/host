//go:build linux

package nativecrash

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const containerHelper = "/usr/local/libexec/hypermesh/crash-sdk/bin/host-container-cleanup"
const containerLibrary = "/usr/local/libexec/hypermesh/crash-sdk/bin/libhypermesh_host_crash.so"

type DockerRunner func(context.Context, ...string) ([]byte, error)
type containerSession struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	done   chan error
	mounts containerMounts
}
type containerMounts struct {
	RunID    string `json:"run_id"`
	Database string `json:"database"`
	Control  string `json:"control"`
}

// ContainerManager is shared by all container runtime choices in one Host agent.
// No helper starts until an explicitly configured lease asks for capture.
type ContainerManager struct {
	state    string
	report   func(Report)
	mu       sync.Mutex
	sessions map[string]*containerSession
}

func NewContainerManager(state string, report func(Report)) *ContainerManager {
	return &ContainerManager{state: state, report: report, sessions: make(map[string]*containerSession)}
}
func (s *containerSession) send(value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return ErrUnavailable
	}
	bytes = append(bytes, '\n')
	done := make(chan error, 1)
	go func() { _, err := s.input.Write(bytes); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		return ErrUnavailable
	}
}
func (s *containerSession) receive(value any) error {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { line, err := s.output.ReadSlice('\n'); done <- result{line, err} }()
	select {
	case r := <-done:
		if r.err != nil || len(r.data) > 4096 {
			return ErrUnavailable
		}
		d := json.NewDecoder(bytes.NewReader(r.data))
		d.DisallowUnknownFields()
		if d.Decode(value) != nil {
			return ErrUnavailable
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return ErrUnavailable
		}
		return nil
	case <-time.After(5 * time.Second):
		return ErrUnavailable
	}
}
func (s *containerSession) abort() {
	s.input.Close()
	select {
	case <-s.done:
		return
	case <-time.After(2 * time.Second):
	}
	_ = s.cmd.Process.Kill()
	<-s.done
}
func containerArgs(args []string, m containerMounts) ([]string, error) {
	if len(args) < 4 || args[0] != "run" || args[len(args)-2] != "-c" {
		return nil, ErrUnavailable
	}
	for _, path := range []string{m.Database, m.Control} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, ":\x00\r\n,") {
			return nil, ErrUnavailable
		}
	}
	// The workload waits before exec; Host binds the already-running container's
	// exact init process, then creates the read-only public configuration.
	prefix := "test -f " + containerLibrary + " || exit 125; n=0; while ! test -s /run/hypermesh-crash/public.json; do n=$((n+1)); test \"$n\" -lt 400 || exit 125; sleep 0.05; done; export LD_PRELOAD=" + containerLibrary + "; "
	out := []string{"run", "-v", m.Database + ":/var/lib/hypermesh-crash/database:rw", "-v", m.Control + ":/run/hypermesh-crash:ro", "-e", "HYPERMESH_HOST_NATIVE_CRASH_ENABLED=1", "-e", "HYPERMESH_HOST_CRASH_DELEGATED=1"}
	out = append(out, args[1:]...)
	out[len(out)-1] = prefix + args[len(args)-1]
	return out, nil
}
func (m *ContainerManager) prepare() (*containerSession, error) {
	if os.Geteuid() != 0 || private(m.state, false) != nil || installedLibrary(containerHelper) != nil {
		return nil, ErrUnavailable
	}
	cmd := exec.Command(containerHelper)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, ErrUnavailable
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, ErrUnavailable
	}
	// No inherited preload, arbitrary library lookup or capture metadata reaches
	// the privileged helper. It needs only the system's ordinary executable path.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if cmd.Start() != nil {
		input.Close()
		return nil, ErrUnavailable
	}
	s := &containerSession{cmd: cmd, input: input, output: bufio.NewReaderSize(output, 4097), done: make(chan error, 1)}
	go func() { s.done <- cmd.Wait() }()
	if s.send(map[string]string{"state_path": m.state}) != nil || s.receive(&s.mounts) != nil {
		s.abort()
		return nil, ErrUnavailable
	}
	directory, err := root()
	if err != nil {
		s.abort()
		return nil, ErrUnavailable
	}
	if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`).MatchString(s.mounts.RunID) || s.mounts.Database != filepath.Join(directory, "crash-runs", s.mounts.RunID, "database") || s.mounts.Control != filepath.Join(directory, "controls", s.mounts.RunID) || private(s.mounts.Database, true) != nil || private(s.mounts.Control, true) != nil {
		s.abort()
		return nil, ErrUnavailable
	}
	return s, nil
}

// Consume Docker's record before the helper publishes its control directory.
// Return a valid ID even if removal fails so failure cleanup can still target it.
func consumeContainerID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	removeErr := os.Remove(path)
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
		return "", ErrUnavailable
	}
	return id, removeErr
}

// Start may use the original no-capture path only before a container is started.
// After Docker starts anything, failure stops/removes that exact container and
// never repeats model execution.
func (m *ContainerManager) Start(ctx context.Context, run func(context.Context, ...string) ([]byte, error), args []string) ([]byte, error) {
	s, err := m.prepare()
	if err != nil {
		return run(ctx, args...)
	}
	launch, err := containerArgs(args, s.mounts)
	if err != nil {
		s.abort()
		return nil, err
	}
	// Docker writes the exact created ID even if its response is interrupted.
	// This path is Host-owned; the worker sees the control mount read-only.
	cidfile := filepath.Join(s.mounts.Control, "docker.cid")
	launch = append([]string{launch[0], "--cidfile", cidfile}, launch[1:]...)
	out, launchErr := run(ctx, launch...)
	id, readErr := consumeContainerID(cidfile)
	validID := regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id)
	fail := func() ([]byte, error) {
		s.abort()
		if validID {
			clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = run(clean, "rm", "-f", id)
		}
		return nil, ErrUnavailable
	}
	if launchErr != nil || readErr != nil || !validID || strings.TrimSpace(string(out)) != id {
		return fail()
	}
	raw, err := run(ctx, "inspect", "--format", "{{json .}}", id)
	if err != nil {
		return fail()
	}
	var state struct {
		ID    string `json:"Id"`
		State struct {
			Pid     int
			Running bool
		}
		HostConfig struct {
			PidMode    string
			Privileged bool
		}
	}
	if len(raw) > 1024*1024 || json.Unmarshal(raw, &state) != nil || state.ID != id || !state.State.Running || state.State.Pid <= 1 || state.HostConfig.Privileged || state.HostConfig.PidMode != "" {
		return fail()
	}
	if s.send(map[string]any{"worker": id, "init_pid": state.State.Pid}) != nil {
		return fail()
	}
	var ready struct {
		Ready bool `json:"ready"`
	}
	if s.receive(&ready) != nil || !ready.Ready {
		return fail()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[id]; exists {
		return fail()
	}
	m.sessions[id] = s
	return out, nil
}
func (m *ContainerManager) Finish(ctx context.Context, id string, stopped bool) error {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	if !stopped {
		s.abort()
		return ErrUnavailable
	}
	if s.send(map[string]bool{"stopped": true}) != nil {
		s.abort()
		return ErrUnavailable
	}
	s.input.Close()
	select {
	case err := <-s.done:
		if err != nil {
			return ErrUnavailable
		}
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
		return ErrUnavailable
	}
	directory, err := root()
	if err != nil {
		return ErrUnavailable
	}
	reports, err := collectContext(ctx, directory, s.mounts.RunID)
	if err != nil {
		return err
	}
	if m.report != nil {
		for _, report := range reports {
			m.report(report)
		}
	}
	return nil
}
