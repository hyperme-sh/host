package trustedmeter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func copyVerified(source, destination, digest string, limit int64) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".meter-artifact-")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer os.Remove(temporary)
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, limit+1))
	if err == nil && (count < 1 || count > limit || hex.EncodeToString(hash.Sum(nil)) != digest) {
		err = ErrInvalid
	}
	if err == nil {
		err = output.Chmod(0400)
	}
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, destination)
}
func LeaseDirectory(stateDir, lease string) (string, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) == string(filepath.Separator) || !uuidPattern.MatchString(lease) {
		return "", ErrInvalid
	}
	return filepath.Join(stateDir, "trusted-meter", lease), nil
}

// PrepareLaunch stages exact downloaded boot artifacts and one model file.
// Only the count journal is retained when the workload stops.
func PrepareLaunch(bundleDir, stateDir string, b Binding, modelPath string, port int) (Bundle, []string, error) {
	if err := ReserveHostJournal(stateDir, b.LeaseID); err != nil {
		return Bundle{}, nil, err
	}
	bundle, err := LoadBundle(bundleDir, b)
	if err != nil {
		return bundle, nil, err
	}
	root, err := LeaseDirectory(stateDir, b.LeaseID)
	if err != nil {
		return bundle, nil, err
	}
	boot, input, journal := filepath.Join(root, "boot"), filepath.Join(root, "input"), filepath.Join(root, "journal")
	args, err := LaunchArgs(bundle, boot, input, journal, port)
	if err != nil {
		return bundle, nil, err
	}
	model, err := os.Open(modelPath)
	if err != nil {
		return bundle, nil, err
	}
	defer model.Close()
	info, err := model.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8<<30 {
		return bundle, nil, ErrInvalid
	}
	if info.Size()*2+(2<<30) > int64(bundle.MemoryMiB)<<20 {
		return bundle, nil, ErrInvalid
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, model); err != nil {
		return bundle, nil, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != b.ModelSHA256 {
		return bundle, nil, ErrInvalid
	}
	for _, dir := range []string{boot, input, journal} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return bundle, nil, err
		}
	}
	for _, artifact := range []struct {
		name, hash string
		limit      int64
	}{{"firmware.fd", bundle.FirmwareSHA256, 64 << 20}, {"kernel", bundle.KernelSHA256, 256 << 20}, {"initrd.cpio", bundle.InitrdSHA256, 512 << 20}} {
		if err = copyVerified(filepath.Join(bundleDir, artifact.name), filepath.Join(boot, artifact.name), artifact.hash, artifact.limit); err != nil {
			return bundle, nil, err
		}
	}
	// Link only the selected model, never export a directory of other tenants' models.
	temp, err := os.CreateTemp(input, ".model-")
	if err != nil {
		return bundle, nil, err
	}
	temporary := temp.Name()
	temp.Close()
	os.Remove(temporary)
	defer os.Remove(temporary)
	if err = os.Link(modelPath, temporary); err != nil {
		// Different filesystems require a verified private staging copy.
		if err = copyVerified(modelPath, temporary, b.ModelSHA256, 8<<30); err != nil {
			return bundle, nil, err
		}
	}
	if err = os.Rename(temporary, filepath.Join(input, "model.gguf")); err != nil {
		return bundle, nil, err
	}
	raw, err := MarshalBinding(b)
	if err != nil {
		return bundle, nil, err
	}
	if err = os.WriteFile(filepath.Join(input, "binding.json"), raw, 0400); err != nil {
		return bundle, nil, err
	}
	return bundle, args, nil
}

func CleanStoppedLaunch(stateDir, lease string) error {
	root, err := LeaseDirectory(stateDir, lease)
	if err != nil {
		return err
	}
	for _, name := range []string{"boot", "input"} {
		if err = os.RemoveAll(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	// Empty retired histories need not accumulate per-lease directories.
	journal := filepath.Join(root, "journal")
	if err = os.Remove(journal); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) {
		return err
	}
	if err == nil || os.IsNotExist(err) {
		if err = os.Remove(root); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
	}
	return nil
}
