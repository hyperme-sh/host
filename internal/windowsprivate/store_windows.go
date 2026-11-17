//go:build windows

// Package windowsprivate owns the crash service's LocalSystem-only registry store.
package windowsprivate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const keyPath = `SOFTWARE\HypermeshCrashService`
const keySD = "O:SYG:SYD:P(A;;KA;;;SY)"
const mutexSD = "O:SYG:SYD:P(A;;0x1f0001;;;SY)"

var advapi = windows.NewLazySystemDLL("advapi32.dll")
var createKey = advapi.NewProc("RegCreateKeyExW")
var flushKey = advapi.NewProc("RegFlushKey")
var namespaceOnce sync.Once
var namespaceHandle uintptr
var namespaceError error
var ErrPrivate = errors.New("private Windows machine store refused")

func RequireSystem() error {
	t := windows.GetCurrentProcessToken()
	u, err := t.GetTokenUser()
	restricted, re := t.IsRestricted()
	if err != nil || re != nil || restricted || u.User.Sid.String() != "S-1-5-18" {
		return ErrPrivate
	}
	return nil
}

func descriptorMatches(h windows.Handle, kind windows.SE_OBJECT_TYPE, want string) bool {
	sd, err := windows.GetSecurityInfo(h, kind, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	expected, e := windows.SecurityDescriptorFromString(want)
	return err == nil && e == nil && sd.String() == expected.String()
}

func openKey(root registry.Key, path, descriptor string) (registry.Key, error) {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return 0, ErrPrivate
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, ErrPrivate
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var h windows.Handle
	var disposition uint32
	result, _, _ := createKey.Call(uintptr(root), uintptr(unsafe.Pointer(name)), 0, 0, 0,
		uintptr(registry.READ|registry.WRITE|registry.WOW64_64KEY), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	runtime.KeepAlive(sd)
	if result != 0 {
		return 0, ErrPrivate
	}
	k := registry.Key(h)
	if !descriptorMatches(h, windows.SE_REGISTRY_KEY, descriptor) {
		k.Close()
		return 0, ErrPrivate
	}
	return k, nil
}

// WithStore serializes all updates across processes. Windows mutex ownership is
// thread-bound, so the goroutine stays on this thread until the mutex is released.
func WithStore(ctx context.Context, action func(registry.Key) error) error {
	if RequireSystem() != nil {
		return ErrPrivate
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespaceOnce.Do(func() { namespaceHandle, namespaceError = systemNamespace() })
	if namespaceError != nil || namespaceHandle == 0 {
		return ErrPrivate
	}
	sd, err := windows.SecurityDescriptorFromString(mutexSD)
	if err != nil {
		return ErrPrivate
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, _ := windows.UTF16PtrFromString(`HypermeshCrashServicePrivateV1\Store`)
	h, err := windows.CreateMutex(&sa, false, name)
	runtime.KeepAlive(sd)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return ErrPrivate
	}
	defer windows.CloseHandle(h)
	if !descriptorMatches(h, windows.SE_KERNEL_OBJECT, mutexSD) {
		return ErrPrivate
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := windows.WaitForSingleObject(h, 50)
		if err != nil {
			return ErrPrivate
		}
		if status == windows.WAIT_OBJECT_0 || status == windows.WAIT_ABANDONED {
			break
		}
		if status != uint32(windows.WAIT_TIMEOUT) {
			return ErrPrivate
		}
	}
	defer windows.ReleaseMutex(h)
	k, err := openKey(registry.LOCAL_MACHINE, keyPath, keySD)
	if err != nil {
		return err
	}
	defer k.Close()
	return action(k)
}

// Data is DPAPI protected as the service account, without the machine-wide flag.
func protect(raw []byte, decrypt bool) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 131072 {
		return nil, ErrPrivate
	}
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	var out windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, ErrPrivate
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if out.Size == 0 || out.Size > 131072 {
		return nil, ErrPrivate
	}
	return bytes.Clone(unsafe.Slice(out.Data, int(out.Size))), nil
}

func Read(k registry.Key, name string) ([]byte, error) {
	raw, _, err := k.GetBinaryValue(name)
	if err != nil {
		return nil, err
	}
	return protect(raw, true)
}
func Write(k registry.Key, name string, raw []byte) error {
	encrypted, err := protect(raw, false)
	if err != nil {
		return err
	}
	if err = k.SetBinaryValue(name, encrypted); err != nil {
		return ErrPrivate
	}
	result, _, _ := flushKey.Call(uintptr(k))
	if result != 0 {
		return fmt.Errorf("private machine checkpoint flush failed")
	}
	return nil
}

// Keep one namespace handle for the process lifetime. The System SID boundary
// prevents another account from creating this namespace first; its DACL also
// prevents opening it from outside that boundary. An alias alone is not trust.
func systemNamespace() (uintptr, error) {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	createBoundary := kernel.NewProc("CreateBoundaryDescriptorW")
	addSID := kernel.NewProc("AddSIDToBoundaryDescriptor")
	deleteBoundary := kernel.NewProc("DeleteBoundaryDescriptor")
	createNamespace := kernel.NewProc("CreatePrivateNamespaceW")
	openNamespace := kernel.NewProc("OpenPrivateNamespaceW")
	for _, proc := range []*windows.LazyProc{createBoundary, addSID, deleteBoundary, createNamespace, openNamespace} {
		if proc.Find() != nil {
			return 0, ErrPrivate
		}
	}
	name, _ := windows.UTF16PtrFromString("HypermeshCrashServiceSystemBoundaryV1")
	boundary, _, _ := createBoundary.Call(uintptr(unsafe.Pointer(name)), 0)
	if boundary == 0 {
		return 0, ErrPrivate
	}
	defer func() { deleteBoundary.Call(boundary) }()
	sid, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return 0, ErrPrivate
	}
	ok, _, _ := addSID.Call(uintptr(unsafe.Pointer(&boundary)), uintptr(unsafe.Pointer(sid)))
	runtime.KeepAlive(sid)
	if ok == 0 {
		return 0, ErrPrivate
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;GA;;;SY)")
	if err != nil {
		return 0, ErrPrivate
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	alias, _ := windows.UTF16PtrFromString("HypermeshCrashServicePrivateV1")
	h, _, callErr := createNamespace.Call(uintptr(unsafe.Pointer(&sa)), boundary, uintptr(unsafe.Pointer(alias)))
	runtime.KeepAlive(sd)
	if h == 0 && errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
		h, _, _ = openNamespace.Call(boundary, uintptr(unsafe.Pointer(alias)))
	}
	if h == 0 {
		return 0, ErrPrivate
	}
	return h, nil
}
