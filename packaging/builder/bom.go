// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/goreleaser/nfpm/v2/files"
)

var pypiNameSeparators = regexp.MustCompile(`[-_.]+`)

// bomComponent is the format-neutral inventory entry for one bundled upstream
// component. The serialized BOM documents are projections of this type, so
// adding a BOM format means adding a marshaller rather than a second inventory.
type bomComponent struct {
	Type    string
	Name    string
	Version string
	PURL    string
}

// bomFormat is one serialization of the shared component inventory.
type bomFormat struct {
	fileName string
	marshal  func(packageName string, components []bomComponent) ([]byte, error)
}

func installedBOMFormats() []bomFormat {
	return []bomFormat{
		{fileName: cycloneDXBOMFileName, marshal: marshalCycloneDXBOM},
		{fileName: spdxBOMFileName, marshal: marshalSPDXBOM},
	}
}

// writeInstalledBOMs stages one document per supported BOM format from a single
// canonical component inventory, so the documents cannot disagree about what the
// package contains.
func writeInstalledBOMs(stagingDir, packageName string, components []bomComponent) (files.Contents, error) {
	components, err := canonicalBOMComponents(components)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("cannot write an empty BOM for %s", packageName)
	}

	formats := installedBOMFormats()
	contents := make(files.Contents, 0, len(formats))
	for _, format := range formats {
		data, err := format.marshal(packageName, components)
		if err != nil {
			return nil, fmt.Errorf("marshalling %s: %w", format.fileName, err)
		}

		path := filepath.Join(stagingDir, format.fileName)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, fmt.Errorf("writing %s: %w", format.fileName, err)
		}

		contents = append(contents, regularFile(path, bomDocPath(packageName, format.fileName), 0o644))
	}

	return contents, nil
}

func canonicalBOMComponents(components []bomComponent) ([]bomComponent, error) {
	seen := make(map[string]struct{}, len(components))
	canonical := make([]bomComponent, 0, len(components))

	for _, component := range components {
		component.Type = strings.TrimSpace(component.Type)
		component.Name = strings.TrimSpace(component.Name)
		component.Version = strings.TrimSpace(component.Version)
		component.PURL = strings.TrimSpace(component.PURL)

		if component.Type == "" || component.Name == "" || component.Version == "" {
			return nil, fmt.Errorf(
				"invalid BOM component: type, name, and version are required (got type=%q name=%q version=%q)",
				component.Type, component.Name, component.Version,
			)
		}

		key := strings.Join([]string{component.Type, component.Name, component.Version, component.PURL}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		canonical = append(canonical, component)
	}

	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Name != canonical[j].Name {
			return canonical[i].Name < canonical[j].Name
		}
		if canonical[i].Version != canonical[j].Version {
			return canonical[i].Version < canonical[j].Version
		}
		if canonical[i].Type != canonical[j].Type {
			return canonical[i].Type < canonical[j].Type
		}
		return canonical[i].PURL < canonical[j].PURL
	})
	return canonical, nil
}

func nodejsBOMComponents(root string) ([]bomComponent, error) {
	var components []bomComponent

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "package.json" || !isNodeModulesPackageManifest(root, path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var pkg struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			return fmt.Errorf("package manifest %s has no name or version", path)
		}

		components = append(components, bomComponent{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    npmPackageURL(pkg.Name, pkg.Version),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventorying Node.js packages: %w", err)
	}

	return canonicalBOMComponents(components)
}

func isNodeModulesPackageManifest(root, manifestPath string) bool {
	rel, err := filepath.Rel(root, manifestPath)
	if err != nil {
		return false
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 3 || parts[len(parts)-1] != "package.json" {
		return false
	}

	nodeModules := -1
	for i := len(parts) - 2; i >= 0; i-- {
		if parts[i] == "node_modules" {
			nodeModules = i
			break
		}
	}
	if nodeModules < 0 {
		return false
	}

	tail := parts[nodeModules+1:]
	switch len(tail) {
	case 2:
		return tail[0] != "" && !strings.HasPrefix(tail[0], "@") && tail[1] == "package.json"
	case 3:
		return strings.HasPrefix(tail[0], "@") && tail[1] != "" && tail[2] == "package.json"
	default:
		return false
	}
}

func npmPackageURL(name, version string) string {
	if scope, pkg, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return fmt.Sprintf("pkg:npm/%s/%s@%s",
			url.QueryEscape(scope),
			url.QueryEscape(pkg),
			url.QueryEscape(version),
		)
	}
	return fmt.Sprintf("pkg:npm/%s@%s", url.QueryEscape(name), url.QueryEscape(version))
}

func pythonBOMComponents(installDir string) ([]bomComponent, error) {
	entries, err := os.ReadDir(installDir)
	if err != nil {
		return nil, fmt.Errorf("reading Python install directory: %w", err)
	}

	var components []bomComponent
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}

		metadataPath := filepath.Join(installDir, entry.Name(), "METADATA")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", metadataPath, err)
		}

		name, version := parseMetadata(string(data))
		if name == "" || version == "" {
			return nil, fmt.Errorf("Python metadata %s has no name or version", metadataPath)
		}

		components = append(components, bomComponent{
			Type:    "library",
			Name:    name,
			Version: version,
			PURL:    pythonPackageURL(name, version),
		})
	}

	return canonicalBOMComponents(components)
}

func pythonPackageURL(name, version string) string {
	normalizedName := pypiNameSeparators.ReplaceAllString(strings.ToLower(name), "-")
	return fmt.Sprintf("pkg:pypi/%s@%s", url.QueryEscape(normalizedName), url.QueryEscape(version))
}

func releaseBOMComponent(cfg Config, componentDir, name string) (bomComponent, error) {
	version, err := readReleaseVersion(filepath.Join(cfg.PackagingDir, "common", componentDir, "release.txt"))
	if err != nil {
		return bomComponent{}, fmt.Errorf("reading %s release version: %w", componentDir, err)
	}

	return bomComponent{
		Type:    "library",
		Name:    name,
		Version: strings.TrimPrefix(version, "v"),
	}, nil
}

func bomDocPath(packageName, fileName string) string {
	return "/usr/share/doc/" + packageName + "/" + fileName
}
