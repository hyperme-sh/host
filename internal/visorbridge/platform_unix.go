//go:build linux || darwin

package visorbridge

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func trustedPath(path string, executable bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refused
	}
	st, err := os.Lstat(path)
	if err != nil {
		return refused
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || stat.Nlink != 1 {
		return refused
	}
	if executable && st.Mode().Perm()&0100 == 0 {
		return refused
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, err = os.Lstat(dir)
		if err != nil {
			return refused
		}
		stat, ok = st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (st.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0)) {
			return refused
		}
		if dir == "/" {
			break
		}
	}
	return nil
}
func Load(path string) (Config, error) {
	var c Config
	if trustedPath(path, false) != nil {
		return c, refused
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, refused
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 || decode(raw, &c) != nil {
		return c, refused
	}
	return c, nil
}
func (b *Bridge) Serve(ctx context.Context) error {
	if !b.config.FeedbackOnly && trustedExecutable(b.config.Conductor) != nil {
		return refused
	}
	return serveSocket(ctx, b.config.Socket, b.config.ClientUID, b.Handler())
}
func serveSocket(ctx context.Context, path string, clientUID uint32, handler http.Handler) error {
	if os.Geteuid() != 0 {
		return refused
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refused
	}
	// An existing root-owned directory is required. It may be traversable by the
	// Visor account, but nobody else may replace the socket or its parents.
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil {
			return refused
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || stat.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
			return refused
		}
		if dir == "/" {
			break
		}
	}
	// Never unlink an unknown or live endpoint to start another server.
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return refused
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return refused
	}
	defer listener.Close()
	mode := os.FileMode(0666)
	if clientUID == 0 {
		mode = 0600
	}
	if os.Chmod(path, mode) != nil {
		return refused
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		uid, err := peerUID(c)
		if err != nil {
			return ctx
		}
		return context.WithValue(ctx, peerKey{}, uid)
	}}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	if err = server.Serve(&peerListener{UnixListener: listener, uid: clientUID, slots: make(chan struct{}, 32)}); err != nil && err != http.ErrServerClosed {
		return refused
	}
	return nil
}

type peerListener struct {
	*net.UnixListener
	uid   uint32
	slots chan struct{}
}
type peerConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *peerConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(connection)
		if err != nil || (uid != l.uid && uid != 0) {
			connection.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &peerConnection{Conn: connection, release: func() { <-l.slots }}, nil
		default:
			connection.Close()
		}
	}
}
