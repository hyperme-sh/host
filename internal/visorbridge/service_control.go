package visorbridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

type UserServiceConfig struct {
	Executable string   `json:"executable"`
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	Units      []string `json:"units"`
}
type serviceArguments struct {
	Verb           string `json:"verb"`
	Executable     string `json:"executable"`
	ExecutableHash string `json:"executable_sha256"`
	Unit           string `json:"unit"`
	UID            uint32 `json:"uid"`
	BindingHash    string `json:"controller_binding_sha256"`
}

func (b *Bridge) serviceBinding() (string, error) {
	c := b.config.ServiceControl
	if c == nil || c.UID == 0 || c.GID == 0 || c.UID != b.config.ClientUID || c.Executable != "/usr/bin/systemctl" || len(c.Units) == 0 || len(c.Units) > 32 {
		return "", refused
	}
	pattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,120}\.service$`)
	for _, unit := range c.Units {
		if !pattern.MatchString(unit) {
			return "", refused
		}
	}
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (b *Bridge) serviceCall(raw []byte, executableHash string) (serviceArguments, error) {
	var action struct {
		Operation string          `json:"operation"`
		Target    string          `json:"target"`
		Arguments string          `json:"arguments_sha256"`
		JSON      string          `json:"arguments_json"`
		Limits    json.RawMessage `json:"limits"`
	}
	if decode(raw, &action) != nil || action.Operation != "service_restart" {
		return serviceArguments{}, refused
	}
	var args serviceArguments
	if decode([]byte(action.JSON), &args) != nil {
		return args, refused
	}
	binding, err := b.serviceBinding()
	if err != nil {
		return args, err
	}
	sum := sha256.Sum256([]byte(action.JSON))
	c := b.config.ServiceControl
	if action.Arguments != hex.EncodeToString(sum[:]) || args.Verb != "restart" || args.Unit != action.Target || !slices.Contains(c.Units, args.Unit) || args.UID != c.UID || args.Executable != c.Executable || args.ExecutableHash != executableHash || args.BindingHash != binding {
		return args, errors.New("Service binding differs")
	}
	return args, nil
}
