package assets

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed firmware/bootloader.bin
var BootloaderBin []byte

//go:embed firmware/partitions.bin
var PartitionsBin []byte

//go:embed firmware/boot_app0.bin
var BootApp0Bin []byte

//go:embed firmware/firmware.bin
var FirmwareBin []byte

//go:embed all:extension
var ExtensionFS embed.FS

func ExtractFirmware(destDir string) (map[string]string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"bootloader.bin": BootloaderBin,
		"partitions.bin": PartitionsBin,
		"boot_app0.bin":  BootApp0Bin,
		"firmware.bin":   FirmwareBin,
	}
	paths := make(map[string]string, len(files))
	for name, data := range files {
		p := filepath.Join(destDir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return nil, err
		}
		paths[name] = p
	}
	return paths, nil
}

func ExtractExtension(destDir string) error {
	return fs.WalkDir(ExtensionFS, "extension", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("extension", path)
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := ExtensionFS.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
