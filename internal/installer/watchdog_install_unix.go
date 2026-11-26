//go:build linux || darwin

package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/buildinfo"
	"github.com/FyberLabs/hypermesh-host/internal/update"
)

const watchdogSystemdService = `[Unit]
Description=Hypermesh Host recovery watchdog
After=network-online.target
ConditionPathExists=/var/lib/hypermesh/activation-approved

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/hypermesh-recovery recovery-watchdog
TimeoutStartSec=4min
`

const watchdogSystemdTimer = `[Unit]
Description=Check Hypermesh Host installation health

[Timer]
OnBootSec=5min
OnUnitInactiveSec=5min

[Install]
WantedBy=timers.target
`

const watchdogLaunchDaemon = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.fyberlabs.hypermesh-recovery</string>
<key>ProgramArguments</key><array>
<string>/usr/local/libexec/hypermesh-recovery</string>
<string>recovery-watchdog</string>
</array>
<key>EnvironmentVariables</key><dict>
<key>PATH</key><string>/usr/local/MacGPG2/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
</dict>
<key>StartInterval</key><integer>300</integer>
<key>StandardOutPath</key><string>/var/log/hypermesh-recovery.log</string>
<key>StandardErrorPath</key><string>/var/log/hypermesh-recovery.log</string>
</dict></plist>
`

func installWatchdog(ctx context.Context, profile recoveryProfile, releaseURL, channel string, build int,
	agentHash string, key []byte, fingerprints []string,
) error {
	stateDir := macPath("", profile.state)
	if err := macDirectory(stateDir, false, true); err != nil {
		return err
	}
	unlock, err := update.LockProfile(filepath.Join(stateDir, update.ProfileLockName))
	if err != nil {
		return err
	}
	defer unlock()
	dir, err := os.MkdirTemp("", "hypermesh-recovery-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	opt := downloadOptions{
		BaseURL: releaseURL, Channel: channel, Arch: runtime.GOARCH, TargetOS: runtime.GOOS,
		Output: filepath.Join(dir, "deploy"), Artifact: "deploy", MinimumBuild: int64(build),
		MatchInstaller: true, Key: key, Fingerprints: fingerprints,
	}
	if _, err := downloadCLI(ctx, opt, fetchArtifact, update.GPGVerify); err != nil {
		return fmt.Errorf("download signed recovery executable: %w", err)
	}
	executable, err := os.ReadFile(opt.Output)
	if err != nil {
		return err
	}
	config, err := json.Marshal(watchdogConfig{Channel: channel, Build: build, SHA256: agentHash,
		Key: key, Fingerprints: fingerprints})
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{
		{profile.executable, executable, 0755},
		{profile.config, config, 0600},
	} {
		if err := installWatchdogFile(file.name, file.body, file.mode); err != nil {
			return err
		}
	}
	if runtime.GOOS == "linux" {
		unitName := "hypermesh-recovery"
		service := watchdogSystemdService
		if profile.name != "standard" {
			unitName += "-" + profile.name
			service = strings.NewReplacer(watchdogExecutable, profile.executable,
				standardRecoveryProfile.condition, profile.condition,
				" recovery-watchdog\n", " recovery-watchdog "+profile.name+"\n").Replace(service)
		}
		for _, file := range []struct{ name, body string }{
			{"service", service}, {"timer", watchdogSystemdTimer},
		} {
			if err := installWatchdogFile("/etc/systemd/system/"+unitName+"."+file.name, []byte(file.body), 0644); err != nil {
				return err
			}
		}
		if _, err := rootWatchdogCommand(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		_, err := rootWatchdogCommand(ctx, "/usr/bin/systemctl", "enable", "--now", unitName+".timer")
		return err
	}
	plist := "/Library/LaunchDaemons/com.fyberlabs.hypermesh-recovery.plist"
	if err := installWatchdogFile(plist, []byte(watchdogLaunchDaemon), 0644); err != nil {
		return err
	}
	if _, err := rootWatchdogCommand(ctx, "/bin/launchctl", "print", "system/com.fyberlabs.hypermesh-recovery"); err == nil {
		return nil
	}
	_, err = rootWatchdogCommand(ctx, "/bin/launchctl", "bootstrap", "system", plist)
	return err
}

func installWatchdogFile(path string, body []byte, mode os.FileMode) error {
	path = macPath("", path)
	dir := filepath.Dir(path)
	if err := macDirectory(dir, true, false); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if _, err := macRead(path, mode, 128<<20); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".hypermesh-recovery-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func installMacWatchdog(ctx context.Context, agent []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := watchdogRead(exe+".install.json", 64<<10)
	if err != nil {
		return fmt.Errorf("read signed installer metadata: %w", err)
	}
	var source struct {
		Schema      int    `json:"schema"`
		Channel     string `json:"channel"`
		Build       int    `json:"build"`
		Commit      string `json:"commit"`
		ReleaseURL  string `json:"release_url"`
		Key         string `json:"trusted_key"`
		Fingerprint string `json:"fingerprint"`
	}
	if json.Unmarshal(raw, &source) != nil || source.Schema != 1 || source.Build <= 0 ||
		source.Build != buildinfo.CurrentBuild() || source.Commit != buildinfo.Current() ||
		source.Channel != buildinfo.CurrentChannel() {
		return errors.New("recovery requires metadata from the signed macOS installer")
	}
	key, err := watchdogRead(source.Key, 128<<10)
	if err != nil {
		return fmt.Errorf("read recovery signing key: %w", err)
	}
	fingerprints, err := update.ParseFingerprints(source.Fingerprint)
	if err != nil || len(fingerprints) == 0 {
		return errors.New("invalid recovery signing fingerprint")
	}
	dir, err := os.MkdirTemp("", "hypermesh-recovery-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	opt := downloadOptions{BaseURL: source.ReleaseURL, Channel: source.Channel, Arch: "arm64",
		TargetOS: "darwin", Output: filepath.Join(dir, "agent"), Artifact: "agent",
		MinimumBuild: int64(source.Build), MatchInstaller: true, Key: key, Fingerprints: fingerprints}
	if _, err := downloadCLI(ctx, opt, fetchArtifact, update.GPGVerify); err != nil {
		return err
	}
	digest, err := update.FileSHA256(opt.Output)
	if err != nil || digest != digestSetupBytes(agent) {
		return errors.New("installed macOS agent does not match the signed release")
	}
	return installWatchdog(ctx, standardRecoveryProfile, source.ReleaseURL, source.Channel, source.Build, digest, key, fingerprints)
}
