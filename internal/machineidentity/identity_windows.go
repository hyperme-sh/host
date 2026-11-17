//go:build windows

package machineidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/FyberLabs/hypermesh-host/internal/windowsprivate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows crash signing has one machine-owned enrollment. No caller selects a
// registry path, file, or alternate key namespace.
const DefaultPath = "windows-crash-service"

type windowsJournal struct {
	Active  *state  `json:"active"`
	Retired []state `json:"retired"`
}

func (p Provider) journal(ctx context.Context, action func(*windowsJournal, func(state) error) error) error {
	if p.Path != "" && p.Path != DefaultPath {
		return windowsprivate.ErrPrivate
	}
	return windowsprivate.WithStore(ctx, func(k registry.Key) error {
		var journal windowsJournal
		raw, err := windowsprivate.Read(k, "identity-v1")
		if err == nil {
			if json.Unmarshal(raw, &journal) != nil {
				return windowsprivate.ErrPrivate
			}
		} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		save := func(s state) error {
			journal.Active = &s
			raw, err := json.Marshal(journal)
			if err != nil {
				return err
			}
			return windowsprivate.Write(k, "identity-v1", raw)
		}
		return action(&journal, save)
	})
}
func (p Provider) Token(ctx context.Context, base, tenant, device, request, bootstrap string) (string, error) {
	var result string
	var err error
	base, err = identityBase(base)
	if err != nil {
		return "", err
	}
	err = p.journal(ctx, func(j *windowsJournal, save func(state) error) error {
		for _, old := range j.Retired {
			if old.Device == device {
				return fmt.Errorf("machine enrollment was retired")
			}
		}
		if j.Active == nil {
			if device == "" || request == "" || bootstrap == "" {
				return fmt.Errorf("machine enrollment is required")
			}
			key, err := newKey()
			if err != nil {
				return err
			}
			authority, plane, renewal, err := p.discover(ctx, base, tenant)
			if err != nil {
				return err
			}
			if p.Authority != "" && p.Authority != authority {
				return fmt.Errorf("machine authority mismatch")
			}
			s := state{Schema: 1, Renewal: renewal, Authority: authority, Plane: plane, Base: base, Tenant: tenant, Device: device, Request: request, Key: key}
			if err := save(s); err != nil {
				return err
			}
		}
		var err error
		result, err = p.renew(ctx, *j.Active, base, tenant, device, request, bootstrap, save)
		return err
	})
	return result, err
}
func (p Provider) ExistingToken(ctx context.Context, base, tenant, device, _ string) (string, error) {
	var result string
	var err error
	base, err = identityBase(base)
	if err != nil {
		return "", err
	}
	err = p.journal(ctx, func(j *windowsJournal, save func(state) error) error {
		if j.Active == nil || !j.Active.Bound {
			return fmt.Errorf("machine signing enrollment is not installed")
		}
		var err error
		result, err = p.renew(ctx, *j.Active, base, tenant, device, j.Active.Request, "", save)
		return err
	})
	return result, err
}
func (p Provider) Invalidate(ctx context.Context, token string) error {
	return p.journal(ctx, func(j *windowsJournal, save func(state) error) error {
		if j.Active == nil || j.Active.Token != token {
			return nil
		}
		s := *j.Active
		s.Token = ""
		s.Expires = 0
		return save(s)
	})
}
func (p Provider) Retire(ctx context.Context) error { return p.RetireEnrollment(ctx, "", true) }
func (p Provider) RetireEnrollment(ctx context.Context, device string, _ bool) error {
	if p.Path != "" && p.Path != DefaultPath {
		return windowsprivate.ErrPrivate
	}
	return windowsprivate.WithStore(ctx, func(k registry.Key) error {
		var j windowsJournal
		raw, err := windowsprivate.Read(k, "identity-v1")
		if err == nil {
			if json.Unmarshal(raw, &j) != nil {
				return windowsprivate.ErrPrivate
			}
		} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		if j.Active != nil {
			j.Retired = append(j.Retired, *j.Active)
		} else if device != "" {
			j.Retired = append(j.Retired, state{Schema: 1, Device: device})
		}
		j.Active = nil
		raw, err = json.Marshal(j)
		if err != nil {
			return err
		}
		return windowsprivate.Write(k, "identity-v1", raw)
	})
}
