//go:build linux

package installer

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

const (
	forumHostName = "j4012-1"
	forumState    = "/var/lib/hypermesh-forum-test"
)

var forumTestProfile = isolatedTestProfile{
	description: "s3r.ch forum TEST", class: "nx-volume", state: forumState,
	config: "/etc/hypermesh-forum-test", unit: "/etc/systemd/system/hypermesh-forum-test-agent.service",
	wireguard: "wg-hm-forum", port: "8094", context: "4096",
	validate: validateForumTestScope,
}

func validateForumTestScope(p agentInstallPlan, issuer, dashboard string, fresh Plan) error {
	network, _ := installationNetwork("test")
	if !strings.EqualFold(p.HostName, forumHostName) || normalizedSetupArch(fresh.Hardware.Facts.Arch) != "arm64" ||
		registrationClass("nx-volume", fresh) != nil || p.ControlPlane != network.Plane ||
		issuer != network.Issuer || dashboard != network.Dashboard || p.Channel != "test" ||
		p.Setup.HeadlessRequested || p.Setup.WireGuardMode != "kernel" ||
		p.Setup.ReadinessURL != network.Plane+"/api/v1/hypermesh/public/host-installation" ||
		p.SetupStateDir != forumState+"/installer" ||
		p.Setup.Preflight.Resources.ModelDirectory != forumState+"/models" ||
		fresh.Resources.ModelDirectory != forumState+"/models" {
		return fmt.Errorf("forum TEST setup requires the measured J4012, TEST origins and a separate model directory")
	}
	return nil
}

func RunInstallForumTest(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	flags := flag.NewFlagSet("install-forum-test", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	plan := flags.String("plan", "", "reviewed signed agent plan for the forum TEST profile")
	digest := flags.String("approve-plan", "", "exact agent plan SHA256")
	tenant := flags.String("tenant-id", "", "s3r.ch TEST tenant from the canonical fixture declaration")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *plan == "" || !setupDigestRE.MatchString(*digest) ||
		!hostregistration.UUID.MatchString(*tenant) || os.Geteuid() != 0 {
		fmt.Fprintln(diagnostic, "require root, --plan, --approve-plan and --tenant-id")
		return 2
	}
	name, err := os.Hostname()
	if err != nil || !strings.EqualFold(name, forumHostName) {
		fmt.Fprintln(diagnostic, "forum TEST installation requires the J4012-1 host")
		return 1
	}
	profile := forumTestProfile
	profile.validate = func(p agentInstallPlan, issuer, dashboard string, fresh Plan) error {
		if p.TenantID != *tenant {
			return fmt.Errorf("reviewed plan tenant differs from the forum TEST tenant")
		}
		return validateForumTestScope(p, issuer, dashboard, fresh)
	}
	if err := installIsolatedTest(ctx, *plan, *digest, profile, out, diagnostic); err != nil {
		fmt.Fprintln(diagnostic, err)
		return 1
	}
	return 0
}
