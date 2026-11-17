//go:build windows

// Package windowscrash serves one crash-only pipe from an installed LocalSystem service.
package windowscrash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/FyberLabs/hypermesh-host/internal/machineidentity"
	"github.com/FyberLabs/hypermesh-host/internal/visorbridge"
	"github.com/FyberLabs/hypermesh-host/internal/windowsprivate"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const ServiceName = "HypermeshCrashRegistration"
const PipeName = `\\.\pipe\hypermesh-crash-registration-v1`

var errRefused = errors.New("Windows crash registration refused")
var securityAPI = windows.NewLazySystemDLL("advapi32.dll")
var impersonate = securityAPI.NewProc("ImpersonateNamedPipeClient")
var openThreadToken = securityAPI.NewProc("OpenThreadToken")
var revertToSelf = securityAPI.NewProc("RevertToSelf")

type Config struct {
	Retire    bool   `json:"retire_enrollment,omitempty"`
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	ClientSID string `json:"client_sid"`
	Base      string `json:"plane"`
	Tenant    string `json:"tenant"`
	Device    string `json:"device"`
	Request   string `json:"request_id"`
	Bootstrap string `json:"enrollment_secret,omitempty"`
	Broker    string `json:"registration_url"`
}

func (Config) String() string   { return "[private crash configuration]" }
func (Config) GoString() string { return "[private crash configuration]" }

// An explicit protected ACL makes the config and executable admin/System-only.
func installedFile(path string, directory bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errRefused
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, errRefused
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		f.Close()
		return nil, errRefused
	}
	owner, _, err := sd.Owner()
	if err != nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		f.Close()
		return nil, errRefused
	}
	text := sd.String()
	pos := strings.Index(text, "D:")
	if pos < 0 {
		f.Close()
		return nil, errRefused
	}
	dacl := text[pos:]
	if dacl != "D:P(A;;FA;;;SY)(A;;FA;;;BA)" && dacl != "D:P(A;;FA;;;BA)(A;;FA;;;SY)" {
		f.Close()
		return nil, errRefused
	}
	return f, nil
}
func load() (Config, func(), error) {
	var c Config
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return c, nil, errRefused
	}
	dir := filepath.Join(root, "HypermeshCrashService")
	parent, err := installedFile(dir, true)
	if err != nil {
		return c, nil, err
	}
	closeParent := func() { parent.Close() }
	executable, err := os.Executable()
	if err != nil || !strings.EqualFold(executable, filepath.Join(dir, "hypermesh-crash-service.exe")) {
		closeParent()
		return c, nil, errRefused
	}
	binary, err := installedFile(executable, false)
	if err != nil {
		closeParent()
		return c, nil, err
	}
	binary.Close()
	f, err := installedFile(filepath.Join(dir, "config.json"), false)
	if err != nil {
		closeParent()
		return c, nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		closeParent()
		return c, nil, errRefused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var trailing any
	if d.Decode(&c) != nil || d.Decode(&trailing) != io.EOF || c.Version != 1 {
		closeParent()
		return c, nil, errRefused
	}
	return c, closeParent, nil
}

func pipeDescriptor(sid string) (string, error) {
	parsed, err := windows.StringToSid(sid)
	// Account-shaped local/domain SIDs; token-user equality rejects group use.
	if err != nil || parsed.String() != sid || !strings.HasPrefix(sid, "S-1-5-21-") || len(strings.Split(sid, "-")) != 8 {
		return "", errRefused
	}
	// 0x12019b grants read/write data and attributes, but not CREATE_PIPE_INSTANCE.
	return "O:SYG:SYD:P(A;;FA;;;SY)(A;;0x12019b;;;" + sid + ")", nil
}
func tokenAllowed(token windows.Token, sid string) bool {
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != sid {
		return false
	}
	restricted, err := token.IsRestricted()
	if err != nil || restricted {
		return false
	}
	var needed uint32
	buf := make([]byte, 512)
	if windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &needed) != nil {
		return false
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	value := label.Label.Sid.String()
	if !strings.HasPrefix(value, "S-1-16-") {
		return false
	}
	level, err := strconv.ParseUint(strings.TrimPrefix(value, "S-1-16-"), 10, 32)
	return err == nil && level >= 0x2000
}
func clientAllowed(handle windows.Handle, sid string) bool {
	// Resolve every syscall before entering an identification-only context. Lazy
	// DLL loading itself can need filesystem access that context cannot perform.
	for _, proc := range []*windows.LazyProc{impersonate, openThreadToken, revertToSelf} {
		if proc.Find() != nil {
			return false
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, _ := impersonate.Call(uintptr(handle))
	if ok == 0 {
		return false
	}
	var token windows.Token
	opened, _, _ := openThreadToken.Call(uintptr(windows.CurrentThread()), windows.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	restored, _, _ := revertToSelf.Call()
	if restored == 0 {
		os.Exit(1)
	}
	if opened == 0 {
		return false
	}
	defer token.Close()
	// Query the captured client token only after restoring the service account.
	return tokenAllowed(token, sid)
}

type connKey struct{}

func handler(next http.Handler, sid string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		h, ok := r.Context().Value(connKey{}).(windows.Handle)
		if err != nil || !ok || !clientAllowed(h, sid) {
			http.Error(w, "Unavailable", 403)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r)
	})
}
func serve(ctx context.Context, c Config) error {
	if windowsprivate.RequireSystem() != nil || !c.Enabled || c.Version != 1 {
		return errRefused
	}
	sd, err := pipeDescriptor(c.ClientSID)
	if err != nil {
		return err
	}
	provider := machineidentity.Provider{Path: machineidentity.DefaultPath}
	credential := func(ctx context.Context) (string, error) {
		return provider.ExistingToken(ctx, c.Base, c.Tenant, c.Device, "")
	}
	next, err := visorbridge.NewCrashHandler(c.Base, c.Tenant, c.Device, c.Broker, credential)
	if err != nil {
		return errRefused
	}
	if _, err = provider.Token(ctx, c.Base, c.Tenant, c.Device, c.Request, c.Bootstrap); err != nil {
		return errRefused
	}
	c.Bootstrap = ""
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: sd, InputBufferSize: 4096, OutputBufferSize: 8192})
	if err != nil {
		return errRefused
	}
	defer listener.Close()
	listener = &boundedListener{Listener: listener, slots: make(chan struct{}, 16)}
	server := &http.Server{Handler: handler(next, c.ClientSID), ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 4096,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if f, ok := c.(interface{ Fd() uintptr }); ok {
				return context.WithValue(ctx, connKey{}, windows.Handle(f.Fd()))
			}
			return ctx
		},
	}
	server.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return errRefused
}

type service struct{}

func (service) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	c, closeConfig, err := load()
	if err != nil {
		return false, 1
	}
	defer closeConfig()
	if c.Retire {
		if c.Enabled {
			return false, 1
		}
		if (machineidentity.Provider{}).RetireEnrollment(context.Background(), c.Device, true) != nil {
			return false, 1
		}
		return false, 0
	}
	if !c.Enabled {
		return false, 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c) }()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
func Run() error {
	active, err := svc.IsWindowsService()
	if err != nil || !active || windowsprivate.RequireSystem() != nil {
		return errRefused
	}
	return svc.Run(ServiceName, service{})
}

// Idle clients cannot allocate unbounded server connections.
type boundedListener struct {
	net.Listener
	slots chan struct{}
}
type boundedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *boundedConn) Fd() uintptr {
	if f, ok := c.Conn.(interface{ Fd() uintptr }); ok {
		return f.Fd()
	}
	return 0
}
func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: c, slots: l.slots}, nil
		default:
			c.Close()
		}
	}
}
