//go:build linux

package installer

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	hostlib "github.com/FyberLabs/hypermesh-host/deploy/lib"
	"github.com/FyberLabs/hypermesh-host/internal/agent"
	"github.com/FyberLabs/hypermesh-host/internal/api"
	"github.com/FyberLabs/hypermesh-host/internal/deviceauth"
)

const (
	haloClass  = "amd-halo-vulkan-lab"
	haloState  = "/var/lib/hypermesh-halo-test"
	haloConfig = "/etc/hypermesh-halo-test"
	haloUnit   = "/etc/systemd/system/hypermesh-halo-test-agent.service"
)

type isolatedTestProfile struct {
	description, class, state, config, unit, wireguard, port, context string
	validate                                                                         func(agentInstallPlan, string, string, Plan) error
}

var haloTestProfile = isolatedTestProfile{
	description: "Halo TEST", class: haloClass, state: haloState, config: haloConfig, unit: haloUnit,
	wireguard: "wg-hm-halo-test", port: "8080", context: "32768",
	validate: validateHaloScope,
}

func validateHaloScope(p agentInstallPlan, issuer, dashboard string, fresh Plan) error {
	network, _ := installationNetwork("test")
	if !haloAliasMatches(p.HostName, fresh.Hardware.Facts.Processor) || !haloSetup(fresh) || p.ControlPlane != network.Plane || issuer != network.Issuer ||
		dashboard != network.Dashboard || p.Channel != "test" || p.Setup.HeadlessRequested ||
		p.Setup.ReadinessURL != network.Plane+"/api/v1/hypermesh/public/host-installation" ||
		p.Setup.WireGuardMode != "kernel" || p.Setup.Preflight.Resources.ModelDirectory != haloState+"/models" {
		return fmt.Errorf("Halo setup requires the matching TEST alias, TEST channel, kernel WireGuard and isolated model directory")
	}
	return nil
}

func haloPayload(path string, data []byte, mode uint32) agentPayload {
	return agentPayload{agentFile{path, digestSetupBytes(data), mode}, data}
}

func writeHaloFiles(files []agentPayload) error {
	for _, file := range files {
		if err := agentDirectory(filepath.Dir(file.Path), true); err != nil {
			return err
		}
		exists, err := agentFileMatches(file.Path, file)
		if err != nil {
			return err
		}
		if !exists {
			if err := writeAgentFile(file.Path, file); err != nil {
				return err
			}
		}
	}
	return nil
}

func haloProfile(p agentInstallPlan, j registrationJournal) []agentPayload {
	return isolatedTestAgent(p, j, haloTestProfile)
}

func isolatedTestAgent(p agentInstallPlan, j registrationJournal, profile isolatedTestProfile) []agentPayload {
	binary := profile.config + "/hypermesh-agent"
	keyDir := profile.state + "/registration-keys/" + j.Request.RequestID
	cfg := agent.Config{ControlPlaneURL: p.ControlPlane, TenantID: p.TenantID,
		HostName: strings.ToLower(p.HostName), ManagedDeviceID: j.DeviceID}
	identity, _ := json.Marshal(cfg.RegisteredProfileState(keyDir, j.Request.CredentialPrefix, j.DeviceSecret))
	unadvertised, _ := json.Marshal(agent.SellPosture{SellState: api.SellNA})
	settings := [][2]string{
		{"HYPERMESH_CONTROL_PLANE_URL", cfg.ControlPlaneURL},
		{"HYPERMESH_TENANT_ID", cfg.TenantID},
		{"HYPERMESH_HOST_NAME", cfg.HostName},
		{"HYPERMESH_MANAGED_DEVICE_ID", cfg.ManagedDeviceID},
		{"HYPERMESH_STATE_DIR", profile.state},
		{"HYPERMESH_WG_USERSPACE", "0"},
		{"HYPERMESH_WG_IFACE", profile.wireguard},
		{"HYPERMESH_LISTEN_PORT", profile.port},
		{"HYPERMESH_LLAMA_CTX_SIZE", profile.context},
		{"HYPERMESH_UPDATE_CHANNEL", "test"},
		{"HYPERMESH_UPDATE_PUBKEY", profile.config + "/update-pubkey.asc"},
		{"HYPERMESH_UPDATE_FINGERPRINTS", strings.Join(p.Fingerprints, ",")},
		{"HYPERMESH_UPDATE_BINARY", binary},
	}
	var environment strings.Builder
	for _, setting := range settings {
		fmt.Fprintf(&environment, "%s=%s\n", setting[0], agentEnvValue(setting[1]))
	}
	unit := "[Unit]\nDescription=Hypermesh " + profile.description + " agent\n" +
		"After=network-online.target docker.service\nWants=network-online.target\n" +
		"ConditionPathExists=" + profile.state + "/device.json\n\n" +
		"[Service]\nUser=root\nEnvironmentFile=" + profile.config + "/agent.env\n" +
		"ExecStartPre=" + profile.config + "/update-rollback\nExecStart=" + binary +
		"\nRestart=on-failure\nRestartSec=5\nKillMode=control-group\n\n[Install]\nWantedBy=multi-user.target\n"
	return []agentPayload{
		haloPayload(keyDir+"/hypermesh.key", []byte(j.PrivateKey+"\n"), 0600),
		haloPayload(profile.state+"/sell.json", unadvertised, 0600),
		haloPayload(profile.state+"/device.json", identity, 0600),
		haloPayload(profile.config+"/agent.env", []byte(environment.String()), 0600),
		haloPayload(profile.unit, []byte(unit), 0644),
	}
}

func RunInstallHaloTest(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("install-halo-test", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	plan := flags.String("plan", "", "reviewed signed agent plan for the TEST profile")
	digest := flags.String("approve-plan", "", "exact agent plan SHA256")
	bootstrap := flags.String("bootstrap-info", "", "private signed-bootstrap metadata file used to prepare or resume setup")
	alias := flags.String("host-name", "", "canonical Halo alias for bootstrap setup")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 {
		fmt.Fprintln(diagnostic, "Halo TEST installation requires root and named arguments")
		return 2
	}
	var err error
	switch {
	case *bootstrap != "" && *plan == "" && *digest == "" && *alias != "":
		err = setupHaloTest(ctx, *bootstrap, *alias, out, diagnostic)
	case *bootstrap == "" && *alias == "" && *plan != "" && setupDigestRE.MatchString(*digest):
		err = installHaloTest(ctx, *plan, *digest, out, diagnostic)
	default:
		fmt.Fprintln(diagnostic, "use --bootstrap-info with --host-name, or --plan with --approve-plan")
		return 2
	}
	if err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	return 0
}

func installHaloTest(ctx context.Context, path, digest string, out, diagnostic io.Writer) error {
	return installIsolatedTest(ctx, path, digest, haloTestProfile, out, diagnostic)
}

func installIsolatedTest(ctx context.Context, path, digest string, profile isolatedTestProfile, out, diagnostic io.Writer) error {
	raw, err := readSetupRegular(path, false)
	if err != nil {
		return err
	}
	var p agentInstallPlan
	if err := decodeSetupJSON(raw, &p); err != nil {
		return err
	}
	if p.SHA256 != digest || agentPlanDigest(p) != digest {
		return fmt.Errorf("agent approval digest does not match")
	}
	if err := validateAgentInputs(p); err != nil {
		return err
	}
	network, _ := installationNetwork("test")
	if err := profile.validate(p, network.Issuer, network.Dashboard, p.Setup.Preflight); err != nil {
		return err
	}
	unlock, err := lockSetupState(profile.state)
	if err != nil {
		return err
	}
	defer unlock()
	if err := checkIsolatedUnitPaths(ctx, setupSource{}, profile.unit); err != nil {
		return err
	}
	fresh, err := registrationPreflight(ctx, p, profile.class)
	if err != nil {
		return err
	}
	if err := profile.validate(p, network.Issuer, network.Dashboard, fresh); err != nil {
		return err
	}
	meta, binary, err := fetchAgentPayload(ctx, p)
	if err != nil {
		return err
	}
	if !sameSetupJSON(meta, p.Release) || !sameSetupJSON(agentFileManifest(agentPayloads(p, binary)), p.Files) {
		return fmt.Errorf("verified payloads differ from the approved plan")
	}
	if err := secureSetupDirectory(profile.config, true); err != nil {
		return err
	}
	if err := writeHaloFiles([]agentPayload{
		haloPayload(profile.config+"/hypermesh-agent", binary, 0755),
		haloPayload(profile.config+"/update-rollback", hostlib.Rollback, 0755),
		haloPayload(profile.config+"/update-pubkey.asc", []byte(p.PublicKey), 0644),
	}); err != nil {
		return err
	}

	// One journal per physical host profile prevents a different plan from
	// silently creating another device after a lost completion response.
	journal := filepath.Join(profile.state, "registration.json")
	j, err := loadIsolatedRegistration(journal, p, network, fresh, profile.class)
	if err != nil {
		return err
	}
	save := func(j registrationJournal) error { return saveRegistration(journal, j) }
	remote, err := newRegistrationClient(network.Plane, p.TenantID)
	if err != nil {
		return err
	}
	login := func(ctx context.Context) error {
		token, err := deviceauth.AuthorizeRegistration(ctx, network.Issuer, network.Dashboard, j.Request.RequestID, diagnostic)
		if err != nil {
			return err
		}
		return remote.Login(ctx, token.Bearer(), func(owner string) error {
			if j.Owner != "" && j.Owner != owner {
				return fmt.Errorf("use the original TEST owner")
			}
			j.Owner = owner
			return save(j)
		})
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	publish := func(j registrationJournal) error {
		files := isolatedTestAgent(p, j, profile)
		if err := checkIsolatedUnitPaths(ctx, setupSource{}, profile.unit); err != nil {
			return err
		}
		if err := secureSetupDirectory(filepath.Dir(files[0].Path), true); err != nil {
			return err
		}
		return writeHaloFiles(files)
	}
	if j.State == "registered-inactive" {
		err = publish(j)
	} else if err = login(ctx); err == nil {
		remote.SetSessionRecovery(login)
		checked := preflightRegistrationRemote{remote, func(ctx context.Context) error {
			fresh, err := registrationPreflight(ctx, p, profile.class)
			if err != nil {
				return err
			}
			return profile.validate(p, network.Issuer, network.Dashboard, fresh)
		}}
		err = recoverRegistrationExpiry(func() error {
			return finishRegistration(ctx, &j, checked, save, publish, diagnostic, waitRegistration)
		}, func() error {
			status, err := remote.Get(ctx, j.Request)
			if err != nil {
				return err
			}
			if err := checked.check(ctx); err != nil {
				return err
			}
			j, err = restartRegistration(j, status, p, fresh, func(old registrationJournal) error {
				return archiveRegistration(profile.state, old)
			}, save)
			return err
		}, diagnostic)
	}
	if err != nil {
		return err
	}
	status := publicRegistration(j)
	status.NextAction = "Bind the TEST device to its shared capacity slot before activating the TEST service."
	return json.NewEncoder(out).Encode(status)
}

func loadIsolatedRegistration(path string, p agentInstallPlan, network guidedNetwork, fresh Plan, class string) (registrationJournal, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		j, err := newRegistrationWithPause(p, network.Issuer, network.Dashboard, class, fresh, true)
		if err != nil {
			return j, err
		}
		return j, saveRegistration(path, j)
	}
	var j registrationJournal
	raw, err := readSetupRegular(path, true)
	if err == nil {
		err = decodeSetupJSON(raw, &j)
	}
	if err != nil {
		return j, err
	}
	return j, validateRegistrationWithPause(j, p, network.Issuer, network.Dashboard, class, true)
}

func checkIsolatedUnitPaths(ctx context.Context, source setupSource, unit string) error {
	name := filepath.Base(unit)
	names := []string{name, name + ".d", "service.d"}
	for i, character := range name {
		if character == '-' {
			names = append(names, name[:i+1]+".service.d")
		}
	}
	return checkAgentUnitPathsFor(ctx, source, "", []agentPayload{{agentFile: agentFile{Path: unit}}}, names)
}
