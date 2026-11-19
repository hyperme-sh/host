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

func validateHaloScope(p agentInstallPlan, issuer, dashboard string, fresh Plan) error {
	network, _ := installationNetwork("test")
	processor := fresh.Hardware.Facts.Processor
	alias := strings.ToLower(p.HostName)
	matches := alias == "halo395-1" && halo395Processor.MatchString(processor) ||
		alias == "halo495-1" && halo495Processor.MatchString(processor)
	if !matches || !haloSetup(fresh) || p.ControlPlane != network.Plane || issuer != network.Issuer ||
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
	binary := haloConfig + "/hypermesh-agent"
	keyDir := haloState + "/registration-keys/" + j.Request.RequestID
	cfg := agent.Config{ControlPlaneURL: p.ControlPlane, TenantID: p.TenantID,
		HostName: strings.ToLower(p.HostName), ManagedDeviceID: j.DeviceID}
	identity, _ := json.Marshal(cfg.RegisteredProfileState(keyDir, j.Request.CredentialPrefix, j.DeviceSecret))
	paused, _ := json.Marshal(agent.SellPosture{SellState: api.SellPaused, Source: agent.SellSourceOwner})
	settings := [][2]string{
		{"HYPERMESH_CONTROL_PLANE_URL", cfg.ControlPlaneURL},
		{"HYPERMESH_TENANT_ID", cfg.TenantID},
		{"HYPERMESH_HOST_NAME", cfg.HostName},
		{"HYPERMESH_MANAGED_DEVICE_ID", cfg.ManagedDeviceID},
		{"HYPERMESH_STATE_DIR", haloState},
		{"HYPERMESH_WG_USERSPACE", "0"},
		{"HYPERMESH_WG_IFACE", "wg-hm-halo-test"},
		{"HYPERMESH_LISTEN_PORT", "8080"},
		{"HYPERMESH_LLAMA_CTX_SIZE", "32768"},
		{"HYPERMESH_UPDATE_CHANNEL", "test"},
		{"HYPERMESH_UPDATE_PUBKEY", haloConfig + "/update-pubkey.asc"},
		{"HYPERMESH_UPDATE_FINGERPRINTS", strings.Join(p.Fingerprints, ",")},
		{"HYPERMESH_UPDATE_BINARY", binary},
	}
	var environment strings.Builder
	for _, setting := range settings {
		fmt.Fprintf(&environment, "%s=%s\n", setting[0], agentEnvValue(setting[1]))
	}
	unit := "[Unit]\nDescription=Hypermesh Halo TEST agent\n" +
		"After=network-online.target docker.service\nWants=network-online.target\n" +
		"ConditionPathExists=" + haloState + "/device.json\n\n" +
		"[Service]\nUser=root\nEnvironmentFile=" + haloConfig + "/agent.env\n" +
		"ExecStartPre=" + haloConfig + "/update-rollback\nExecStart=" + binary +
		"\nRestart=on-failure\nRestartSec=5\nKillMode=control-group\n\n[Install]\nWantedBy=multi-user.target\n"
	return []agentPayload{
		haloPayload(keyDir+"/hypermesh.key", []byte(j.PrivateKey+"\n"), 0600),
		haloPayload(haloState+"/sell.json", paused, 0600),
		haloPayload(haloState+"/device.json", identity, 0600),
		haloPayload(haloConfig+"/agent.env", []byte(environment.String()), 0600),
		haloPayload(haloUnit, []byte(unit), 0644),
	}
}

func RunInstallHaloTest(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("install-halo-test", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	plan := flags.String("plan", "", "reviewed signed agent plan for the TEST profile")
	digest := flags.String("approve-plan", "", "exact agent plan SHA256")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *plan == "" || !setupDigestRE.MatchString(*digest) || os.Geteuid() != 0 {
		fmt.Fprintln(diagnostic, "require root, --plan and --approve-plan")
		return 2
	}
	if err := installHaloTest(ctx, *plan, *digest, out, diagnostic); err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	return 0
}

func installHaloTest(ctx context.Context, path, digest string, out, diagnostic io.Writer) error {
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
	if err := validateHaloScope(p, network.Issuer, network.Dashboard, p.Setup.Preflight); err != nil {
		return err
	}
	unlock, err := lockSetupState(haloState)
	if err != nil {
		return err
	}
	defer unlock()
	if err := checkHaloUnitPaths(ctx, setupSource{}); err != nil {
		return err
	}
	fresh, err := registrationPreflight(ctx, p, haloClass)
	if err != nil {
		return err
	}
	if err := validateHaloScope(p, network.Issuer, network.Dashboard, fresh); err != nil {
		return err
	}
	meta, binary, err := fetchAgentPayload(ctx, p)
	if err != nil {
		return err
	}
	if !sameSetupJSON(meta, p.Release) || !sameSetupJSON(agentFileManifest(agentPayloads(p, binary)), p.Files) {
		return fmt.Errorf("verified payloads differ from the approved plan")
	}
	if err := secureSetupDirectory(haloConfig, true); err != nil {
		return err
	}
	if err := writeHaloFiles([]agentPayload{
		haloPayload(haloConfig+"/hypermesh-agent", binary, 0755),
		haloPayload(haloConfig+"/update-rollback", hostlib.Rollback, 0755),
		haloPayload(haloConfig+"/update-pubkey.asc", []byte(p.PublicKey), 0644),
	}); err != nil {
		return err
	}

	// One journal per physical host profile prevents a different plan from
	// silently creating another device after a lost completion response.
	journal := filepath.Join(haloState, "registration.json")
	j, err := loadHaloRegistration(journal, p, network, fresh)
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
		files := haloProfile(p, j)
		if err := checkHaloUnitPaths(ctx, setupSource{}); err != nil {
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
			fresh, err := registrationPreflight(ctx, p, haloClass)
			if err != nil {
				return err
			}
			return validateHaloScope(p, network.Issuer, network.Dashboard, fresh)
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
				return archiveRegistration(haloState, old)
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

func loadHaloRegistration(path string, p agentInstallPlan, network guidedNetwork, fresh Plan) (registrationJournal, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		j, err := newRegistration(p, network.Issuer, network.Dashboard, haloClass, fresh)
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
	return j, validateRegistration(j, p, network.Issuer, network.Dashboard, haloClass)
}

func checkHaloUnitPaths(ctx context.Context, source setupSource) error {
	names := []string{filepath.Base(haloUnit), filepath.Base(haloUnit) + ".d",
		"hypermesh-halo-test-.service.d", "hypermesh-halo-.service.d", "hypermesh-.service.d", "service.d"}
	return checkAgentUnitPathsFor(ctx, source, "", []agentPayload{{agentFile: agentFile{Path: haloUnit}}}, names)
}
