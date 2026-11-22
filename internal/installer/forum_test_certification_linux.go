//go:build linux

package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FyberLabs/hypermesh-host/internal/hostregistration"
)

const (
	forumCertificationTenant = "afee9b29-1706-5590-bbbf-e58df8945ac0"
	forumCertificationDigest = "65b8fcd92af6b4fefa935c625d1ac27ea29dcb6ee14589c55a8f115ceaaa1423"
	forumCertificationModel  = forumState + "/models/" + forumCertificationDigest + ".gguf"
)

func certificationSetupState(forum bool) string {
	if forum {
		return forumState + "/installer"
	}
	return defaultSetupState
}

func validateForumCertificationModel(p certificationPlan) error {
	manifest := p.Run.Manifest
	if p.Agent.TenantID != forumCertificationTenant || manifest.ClassID != forumTestProfile.class ||
		manifest.CatalogID != "qwen-2.5-7b-q4" || manifest.FileHash != "sha256:"+forumCertificationDigest ||
		manifest.SizeBytes != 4683074240 || !manifest.FullContext {
		return fmt.Errorf("certification requires the pinned s3r.ch TEST Qwen workload")
	}
	return nil
}

func readForumCertificationIdentity(p agentInstallPlan) (registrationJournal, error) {
	var journal registrationJournal
	network, _ := installationNetwork("test")
	name, err := os.Hostname()
	if err != nil || !strings.EqualFold(name, forumHostName) || p.TenantID != forumCertificationTenant ||
		p.ControlPlane != network.Plane || p.Channel != "test" || p.SetupStateDir != certificationSetupState(true) {
		return journal, fmt.Errorf("certification requires the dedicated J4012-1 s3r.ch TEST enrollment")
	}
	if err = guidedRead(filepath.Join(forumState, "registration.json"), &journal, true); err != nil {
		return journal, err
	}
	if journal.State != "registered-inactive" ||
		validateRegistrationWithPause(journal, p, network.Issuer, network.Dashboard, forumTestProfile.class, true) != nil {
		return journal, fmt.Errorf("certification requires the current paused TEST registration")
	}
	return journal, nil
}

func scopedCertificationIdentity(p certificationPlan, forum bool) (registrationJournal, *hostregistration.Client, error) {
	if !forum {
		return readCertificationIdentity(p)
	}
	journal, err := readForumCertificationIdentity(p.Agent)
	if err != nil {
		return journal, nil, err
	}
	if journal.DeviceID != p.Run.DeviceID || journal.Request.RequestID != p.Run.RequestID {
		return journal, nil, fmt.Errorf("certification plan belongs to a different TEST enrollment")
	}
	client, err := scopedCertificationClient(p.Agent, true)
	return journal, client, err
}

func scopedCertificationClient(plan agentInstallPlan, forum bool) (*hostregistration.Client, error) {
	if !forum {
		return newRegistrationClient(plan.ControlPlane, plan.TenantID)
	}
	client, err := hostregistration.New(plan.ControlPlane, plan.TenantID)
	if err == nil {
		client.SetMachineIdentity(filepath.Join(forumState, "machine-identity.json"))
	}
	return client, err
}

func scopedCertificationPreflight(ctx context.Context, p certificationPlan, journal registrationJournal, forum bool) error {
	if !forum {
		return certPreflight(ctx, p, journal)
	}
	source := setupSource{}
	for _, unit := range []string{filepath.Base(forumTestProfile.unit), "hypermesh-agent.service", "hypermesh-wg.service"} {
		raw, err := source.output(ctx, "systemctl", "--system", "show", unit, "-p", "ActiveState", "--value")
		if err != nil || strings.TrimSpace(string(raw)) != "inactive" {
			return fmt.Errorf("%s must be inactive for forum TEST certification", unit)
		}
	}
	for _, root := range []string{forumState, "/var/lib/hypermesh"} {
		if _, err := os.Lstat(filepath.Join(root, "lease.json")); !os.IsNotExist(err) {
			return fmt.Errorf("reconcile local leases before forum TEST certification")
		}
	}
	models := forumState + "/models"
	if err := agentDirectory(models, false); err != nil {
		return err
	}
	raw, err := source.output(ctx, "findmnt", "-n", "-o", "SOURCE", "--mountpoint", models)
	if err != nil || strings.TrimSpace(string(raw)) != "/dev/nvme0n1p16" {
		return fmt.Errorf("the dedicated J4012-1 model volume must be mounted")
	}
	fresh, err := registrationPreflight(ctx, p.Agent, forumTestProfile.class)
	if err != nil {
		return err
	}
	if err = validateForumTestScope(p.Agent, journal.Issuer, journal.Dashboard, fresh); err != nil {
		return err
	}
	for _, file := range isolatedTestAgent(p.Agent, journal, forumTestProfile) {
		if err = agentDirectory(filepath.Dir(file.Path), false); err != nil {
			return err
		}
		matches, err := agentFileMatches(file.Path, file)
		if err != nil || !matches {
			return fmt.Errorf("installed TEST identity or paused service configuration differs")
		}
	}
	return nil
}
