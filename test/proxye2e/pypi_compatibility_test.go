package proxye2e

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyFlow_PypiLegacyArtifacts(t *testing.T) {
	var cases []TestCase
	for _, file := range []struct{ filename, name, version string }{
		{"Flask-RESTful-0.3.10-py2.py3-none-any.whl", "flask-restful", "0.3.10"},
		{"evil-pkg-1.0.0-py3-none-any.whl", "evil-pkg", "1.0.0"},
		{"numpy-1.9.2-cp27-none-win32.egg", "numpy", "1.9.2"},
		{"PyYAML-3.10.win32-py2.5.exe", "pyyaml", "3.10"},
	} {
		for _, route := range []struct{ name, host, base string }{
			{"builtin", "files.pythonhosted.org", "/packages"},
			{"custom", "python.example.test", "/simple"},
		} {
			for _, mode := range []struct {
				name              string
				paranoid, blocked bool
			}{
				{name: "default malware", blocked: true},
				{name: "paranoid malware", paranoid: true, blocked: true},
				{name: "paranoid clean", paranoid: true},
			} {
				path := route.base + "/demo/" + file.filename
				cases = append(cases, TestCase{
					Name: mode.name + "/" + route.name + "/" + file.filename,
					Config: func(rc *config.RuntimeConfig) {
						rc.Config.Paranoid = mode.paranoid
						if route.name == "custom" {
							customRegistry("legacy", "pypi", "https://"+route.host+route.base)(rc)
						}
					},
					Setup: func(h *Harness) {
						if route.name == "custom" {
							h.Registry.AddCustomPypi(route.host, route.base)
						}
						verdict := Clean()
						if mode.blocked {
							verdict = VerifiedMalware()
						}
						h.Analyzer.SetPypi(file.name, file.version, verdict)
					},
					Exec: func(h *Harness) ExecResult {
						var res ExecResult
						res.add(h.get("https://"+route.host+path, nil))
						return res
					},
					Assert: func(t *testing.T, h *Harness, res ExecResult) {
						require.Len(t, res.Requests, 1)
						require.NoError(t, res.Requests[0].Err)
						assert.Equal(t, mode.blocked, res.Blocked())
						assert.Equal(t, 1, h.Analyzer.AnalyzedCount(file.name, file.version))
						assert.Equal(t, !mode.blocked, h.Registry.Requested(route.host, path))
						if !mode.blocked {
							assert.Equal(t, 200, res.Requests[0].StatusCode)
						}
					},
				})
			}
		}
	}
	RunCases(t, cases)
}

func TestProxyFlow_PypiImplicitPostRelease(t *testing.T) {
	const (
		name     = "hello-test"
		version  = "1.0.post1"
		filePath = "/packages/source/h/hello-test/hello-test-1.0-1.tar.gz"
	)

	RunCases(t, []TestCase{{
		Name: "implicit post release malware is blocked",
		Setup: func(h *Harness) {
			h.Analyzer.SetPypi(name, version, VerifiedMalware())
		},
		Exec: func(h *Harness) ExecResult {
			var res ExecResult
			res.add(h.get("https://files.pythonhosted.org"+filePath, nil))
			return res
		},
		Assert: func(t *testing.T, h *Harness, res ExecResult) {
			require.Len(t, res.Requests, 1)
			require.NoError(t, res.Requests[0].Err)
			assert.True(t, res.Blocked())
			assert.Equal(t, 1, h.Analyzer.AnalyzedCount(name, version))
			assert.False(t, h.Registry.Requested("files.pythonhosted.org", filePath))
		},
	}})
}

func TestProxyFlow_PypiNormalizedPolicyPins(t *testing.T) {
	var cases []TestCase
	for _, version := range []struct{ raw, normalized string }{
		{"0.6c11", "0.6rc11"}, {"3.05", "3.5"}, {"0.01", "0.1"}, {"0!1.0", "1.0"},
	} {
		for _, policy := range []string{"trusted", "skip", "pinned"} {
			cases = append(cases, TestCase{
				Name:           policy + "/" + version.raw,
				PinnedVersions: map[string]string{"demo": version.raw},
				Config: func(rc *config.RuntimeConfig) {
					rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 2}
					ref := config.TrustedPackage{Purl: "pkg:pypi/demo@" + version.raw}
					switch policy {
					case "trusted":
						rc.Config.TrustedPackages = []config.TrustedPackage{ref}
					case "skip":
						rc.Config.DependencyCooldown.Skip = []config.TrustedPackage{ref}
					}
				},
				Setup: func(h *Harness) {
					h.Registry.AddPypi(PypiPackage{Name: "demo", Versions: []PypiVersion{
						{Version: "0.0", PublishedAt: old()}, {Version: version.raw, PublishedAt: recent()},
					}})
					h.Analyzer.SetPypi("demo", version.raw, VerifiedMalware())
					h.Analyzer.SetPypi("demo", version.normalized, VerifiedMalware())
				},
				Exec: func(h *Harness) ExecResult { return h.Pypi().Install("demo", version.raw) },
				Assert: func(t *testing.T, h *Harness, res ExecResult) {
					switch policy {
					case "trusted":
						assert.False(t, res.Blocked())
						require.Len(t, res.Requests, 2)
						assert.Equal(t, 200, res.Requests[1].StatusCode)
						assert.Empty(t, h.Analyzer.Calls())
						assert.Empty(t, h.CooldownBlocks())
					case "skip":
						assert.True(t, res.Blocked())
						assert.Equal(t, 1, h.Analyzer.AnalyzedCount("demo", version.normalized))
						assert.Empty(t, h.CooldownBlocks())
					case "pinned":
						assert.Empty(t, h.Analyzer.Calls())
						blocks := h.CooldownBlocks()
						require.Len(t, blocks, 1)
						assert.Equal(t, version.raw, blocks[0].Version)
					}
				},
			})
		}
	}
	RunCases(t, cases)
}

func TestProxyFlow_PypiCustomIndexHTML(t *testing.T) {
	var cases []TestCase
	for _, base := range []string{"/simple", "/user/index/+simple"} {
		for _, page := range []string{"/demo/", "/demo/index.html"} {
			cases = append(cases, TestCase{
				Name: base + page,
				Config: func(rc *config.RuntimeConfig) {
					customRegistry("legacy", "pypi", "https://python.example.test"+base)(rc)
					rc.Config.Paranoid = true
					rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 2}
				},
				Setup: func(h *Harness) {
					h.Registry.AddCustomPypi("python.example.test", base)
					h.Registry.AddPypi(PypiPackage{Name: "demo", Versions: []PypiVersion{
						{Version: "1.0", PublishedAt: old()}, {Version: "2.0", PublishedAt: recent()},
						{Version: "3.0", PublishedAt: recent(), Filename: "demo-3.0-py2.7.egg"},
						{Version: "4.0", PublishedAt: recent(), Filename: "demo-4.0.win32-py2.5.exe"},
					}})
				},
				Exec: func(h *Harness) ExecResult {
					var res ExecResult
					res.add(h.get("https://python.example.test"+base+page, map[string]string{"Accept": pypiSimpleContentType}))
					return res
				},
				Assert: func(t *testing.T, h *Harness, res ExecResult) {
					require.Len(t, res.Requests, 1)
					require.NoError(t, res.Requests[0].Err)
					assert.Equal(t, 200, res.Requests[0].StatusCode)
					assert.Contains(t, res.Requests[0].Body, "demo-1.0.tar.gz")
					assert.NotContains(t, res.Requests[0].Body, "demo-2.0.tar.gz")
					assert.NotContains(t, res.Requests[0].Body, ".egg")
					assert.NotContains(t, res.Requests[0].Body, ".exe")
					assert.Empty(t, h.Analyzer.Calls())
				},
			})
		}
	}
	RunCases(t, cases)
}

func TestProxyFlow_PypiSdistSuffixIdentity(t *testing.T) {
	var cases []TestCase
	for _, suffix := range []string{"build2", "linux", "final"} {
		for _, paranoid := range []bool{false, true} {
			filename := "demo-1.0.0-" + suffix + ".tar.gz"
			filePath := "/packages/source/d/demo/" + filename
			mode := "default"
			if paranoid {
				mode = "paranoid"
			}
			cases = append(cases, TestCase{
				Name: suffix + " " + mode,
				Config: func(rc *config.RuntimeConfig) {
					rc.Config.Paranoid = paranoid
					rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 30}
				},
				Setup: func(h *Harness) {
					h.Registry.AddPypi(PypiPackage{Name: "demo", Versions: []PypiVersion{
						{Version: "1.0.0", PublishedAt: old()},
						{Version: "1.0.0-" + suffix, Filename: filename, PublishedAt: recent()},
						{Version: "2.0.0", PublishedAt: recent()},
					}})
					h.Analyzer.SetPypi("demo", "1.0.0", Clean())
					h.Analyzer.SetPypi("demo", "1.0.0-"+suffix, VerifiedMalware())
				},
				Exec: func(h *Harness) ExecResult {
					var res ExecResult
					res.add(h.get("https://pypi.org/simple/demo/", map[string]string{"Accept": pypiSimpleContentType}))
					res.add(h.get("https://files.pythonhosted.org"+filePath, nil))
					return res
				},
				Assert: func(t *testing.T, h *Harness, res ExecResult) {
					require.Len(t, res.Requests, 2)
					for _, req := range res.Requests {
						require.NoError(t, req.Err)
					}
					assert.Equal(t, 200, res.Requests[0].StatusCode)
					assert.Contains(t, res.Requests[0].Body, "demo-1.0.0.tar.gz")
					assert.Contains(t, res.Requests[0].Body, filename)
					assert.NotContains(t, res.Requests[0].Body, "demo-2.0.0.tar.gz")
					assert.Equal(t, paranoid, res.Blocked())
					assert.Equal(t, !paranoid, h.Registry.Requested("files.pythonhosted.org", filePath))
					assert.Empty(t, h.Analyzer.Calls())
				},
			})
		}
	}
	RunCases(t, cases)
}

func TestProxyFlow_PypiRootIndex(t *testing.T) {
	var cases []TestCase
	for _, base := range []string{"/simple", "/user/index/+simple"} {
		for _, page := range []string{"/", "/index.html"} {
			for _, host := range []string{"pypi.org", "python.example.test"} {
				if host == "pypi.org" && base != "/simple" {
					continue
				}
				cases = append(cases, TestCase{
					Name: host + base + page,
					Config: func(rc *config.RuntimeConfig) {
						customRegistry("custom", "pypi", "https://python.example.test"+base)(rc)
						rc.Config.Paranoid = true
						rc.Config.DependencyCooldown = config.DependencyCooldownConfig{Enabled: true, Days: 2}
					},
					Setup: func(h *Harness) { h.Registry.AddCustomPypi("python.example.test", base) },
					Exec: func(h *Harness) ExecResult {
						var res ExecResult
						res.add(h.get("https://"+host+base+page, map[string]string{"Accept": "text/html"}))
						return res
					},
					Assert: func(t *testing.T, h *Harness, res ExecResult) {
						require.Len(t, res.Requests, 1)
						require.NoError(t, res.Requests[0].Err)
						assert.False(t, res.Blocked())
						require.True(t, h.Registry.Requested(host, base+page))
						for _, req := range h.Registry.Requests() {
							assert.Equal(t, "text/html", req.Headers.Get("Accept"))
						}
						assert.Empty(t, h.Analyzer.Calls())
						assert.Empty(t, h.CooldownBlocks())
					},
				})
			}
		}
	}
	RunCases(t, cases)
}
