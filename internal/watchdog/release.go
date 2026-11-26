package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/FyberLabs/hypermesh-host/internal/update"
)

var (
	releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.\-]+)?$`)
	releaseCommit  = regexp.MustCompile(`^[a-f0-9]{40}$`)
)

// Release identifies an artifact only after the signed manifest has been
// checked against the local profile and its last installed build.
type Release struct {
	Manifest update.Manifest
	Binary   string
}

func VerifyRelease(checksums, signature, manifest, publicKey []byte, fingerprints []string,
	channel, platform, arch string, minimumBuild int,
) (Release, error) {
	return verifyRelease(checksums, signature, manifest, publicKey, fingerprints,
		channel, platform, arch, minimumBuild, update.GPGVerify)
}

func verifyRelease(checksums, signature, manifest, publicKey []byte, fingerprints []string,
	channel, platform, arch string, minimumBuild int,
	verify func([]byte, []byte, []byte, []string) error,
) (Release, error) {
	if platform != "linux" && platform != "darwin" ||
		arch != "arm64" && !(platform == "linux" && arch == "amd64") {
		return Release{}, errors.New("unsupported Host recovery platform")
	}
	if channel != update.ChannelTest && channel != update.ChannelProd ||
		minimumBuild <= 0 || len(fingerprints) == 0 ||
		len(checksums) > 512<<10 || len(signature) > 128<<10 || len(manifest) > 64<<10 {
		return Release{}, errors.New("invalid Host recovery release policy")
	}
	if err := verify(checksums, signature, publicKey, fingerprints); err != nil {
		return Release{}, err
	}
	if err := update.CheckHash(checksums, update.ManifestName, manifest); err != nil {
		return Release{}, err
	}
	var release update.Manifest
	if err := json.Unmarshal(manifest, &release); err != nil {
		return Release{}, err
	}
	if release.Channel != channel || release.Build < minimumBuild ||
		!releaseVersion.MatchString(release.Version) || !releaseCommit.MatchString(release.Commit) {
		return Release{}, errors.New("signed release does not match installed Host channel or build")
	}
	id := release.Version
	if channel == update.ChannelTest {
		id = strconv.Itoa(release.Build) + "-" + release.Commit[:12]
	}
	if release.ReleaseID != id {
		return Release{}, errors.New("signed Host release ID mismatch")
	}
	return Release{Manifest: release, Binary: fmt.Sprintf("hypermesh-agent_%s_%s_%s", release.Version, platform, arch)}, nil
}
