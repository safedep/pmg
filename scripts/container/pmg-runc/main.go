//go:build linux

// pmg-runc is an OCI runtime wrapper for the PMG runner image. On "create"
// and "run" it gives the container the PMG CA. On "exec" it gives the new
// process the same trust variables. Then it runs the real runc with the same
// arguments. On any error it leaves the spec unchanged, so it never stops a
// container from starting.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// inDir is under /dev, which the runtime mounts as a tmpfs. So the mount
	// points are not in the file system of the container, and a build does
	// not save them in an image.
	inDir = "/dev/pmg-ca"

	// buildkitWrap is earlier on PATH than buildkitRunc, so BuildKit finds
	// the wrapper first. The real binary stays in its place, because runc
	// must start from a file of the image, not from a bind mount.
	buildkitRunc = "/usr/bin/buildkit-runc"
	buildkitWrap = "/usr/local/bin/buildkit-runc"

	maxCAFile = 16 << 20
)

var (
	// caDirs are the places where the PMG CA files can be. The first is in
	// the runner container. The second is in a container that this wrapper
	// set up, such as a BuildKit container.
	caDirs = []string{"/etc/pmg-runc", inDir}

	// stateDir holds the changes of each container that a "runc exec" must
	// repeat. An exec process does not get the env of the container spec.
	stateDir = "/run/pmg-runc"
	logFile  = "/var/log/pmg-runc.log"

	systemBundles = []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}

	// caVars name a CA file. When an image sets one of them itself, the
	// container gets a copy of that file with the PMG CA added.
	caVars = map[string]bool{
		"SSL_CERT_FILE": true, "REQUESTS_CA_BUNDLE": true, "PIP_CERT": true, "CURL_CA_BUNDLE": true,
		"NODE_EXTRA_CA_CERTS": true, "GIT_SSL_CAINFO": true, "CARGO_HTTP_CAINFO": true,
	}

	globalValueFlags = map[string]bool{"root": true, "log": true, "log-format": true, "criu": true, "rootless": true}

	commandValueFlags = map[string]bool{
		"bundle": true, "b": true, "process": true, "p": true,
		"console-socket": true, "pid-file": true, "preserve-fds": true,
		"cwd": true, "env": true, "e": true, "user": true, "u": true,
		"additional-gids": true, "g": true, "apparmor": true, "process-label": true,
		"cap": true, "c": true, "cgroup": true,
	}
)

// call is a parsed runc command line.
type call struct {
	cmd     string
	bundle  string
	process string
	id      string
}

func main() {
	args := os.Args[1:]
	if err := apply(parseArgs(args)); err != nil {
		logf("%v", err)
	}
	real, err := realRunc(os.Args[0])
	if err != nil {
		exitf("pmg-runc: %v", err)
	}
	if err := syscall.Exec(real, append([]string{real}, args...), os.Environ()); err != nil {
		exitf("pmg-runc: exec %s: %v", real, err)
	}
}

func apply(c call) error {
	if c.id == "" {
		return nil
	}
	switch c.cmd {
	case "create", "run":
		if err := inject(c.bundle, c.id); err != nil {
			return fmt.Errorf("ca not added to %s: %w", c.id, err)
		}
		logf("ca added to %s", c.id)
	case "exec":
		if c.process == "" {
			return nil
		}
		if err := injectExec(c.process, c.id); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("exec env not added to %s: %w", c.id, err)
		}
	case "delete":
		if err := os.Remove(statePath(c.id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove state of %s: %w", c.id, err)
		}
	}
	return nil
}

// parseArgs reads the global flags, the command, the command flags and the
// container ID. runc stops its flag parse at the first positional argument,
// which is the container ID.
func parseArgs(args []string) call {
	var c call
	i := 0
	for ; i < len(args); i++ {
		name, _, inline, ok := splitFlag(args[i])
		if !ok {
			break
		}
		if globalValueFlags[name] && !inline {
			i++
		}
	}
	if i >= len(args) {
		return c
	}
	c.cmd = args[i]
	for i++; i < len(args); i++ {
		name, value, inline, ok := splitFlag(args[i])
		if !ok {
			if args[i] == "--" {
				i++
			}
			if i < len(args) {
				c.id = args[i]
			}
			return c
		}
		if !commandValueFlags[name] {
			continue
		}
		if !inline {
			i++
			if i >= len(args) {
				return c
			}
			value = args[i]
		}
		switch name {
		case "bundle", "b":
			c.bundle = value
		case "process", "p":
			c.process = value
		}
	}
	return c
}

// splitFlag splits "--name=value", "--name" and "-n". It returns ok false for
// a positional argument and for "--".
func splitFlag(a string) (name, value string, inline, ok bool) {
	if len(a) < 2 || a[0] != '-' || a == "--" {
		return "", "", false, false
	}
	name, value, inline = strings.Cut(strings.TrimLeft(a, "-"), "=")
	return name, value, inline, true
}

// realRunc finds the binary that this wrapper stands in for: the first one
// on PATH with the same name that is not this wrapper.
func realRunc(argv0 string) (string, error) {
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return "", err
	}
	names := []string{filepath.Base(argv0), "runc"}
	dirs := append(filepath.SplitList(os.Getenv("PATH")), "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
	for _, name := range names {
		for _, d := range dirs {
			if !filepath.IsAbs(d) {
				continue
			}
			p := filepath.Join(d, name)
			st, err := os.Stat(p)
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 || os.SameFile(st, self) {
				continue
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("no real runc for %s", argv0)
}

func inject(bundle, id string) error {
	if bundle == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		bundle = wd
	}
	dir, ca, err := loadCA()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(bundle, "config.json")
	spec, err := readJSON(cfgPath)
	if err != nil {
		return err
	}
	root := ""
	if r, ok := spec["root"].(map[string]any); ok {
		root, _ = r["path"].(string)
	}
	if root == "" {
		return errors.New("spec has no root path")
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(bundle, root)
	}
	mounts, _ := spec["mounts"].([]any)
	if !devIsTmpfs(mounts) {
		return errors.New("/dev of the container is not a tmpfs")
	}
	bind := func(src, dst string) {
		mounts = append(mounts, map[string]any{"destination": dst, "type": "bind", "source": src, "options": []any{"rbind", "ro"}})
	}

	// The container keeps the CAs of its image: it gets the image bundle
	// plus the PMG CA. A mount over the image bundle makes
	// update-ca-certificates fail, so tools get the merged file from the
	// trust variables.
	bundleFile := filepath.Join(dir, "ca-bundle.pem")
	if own := imageBundle(root); own != nil {
		bundleFile = filepath.Join(bundle, "pmg-ca-bundle.pem")
		if err := writeFile(bundleFile, merge(own, ca), 0o644); err != nil {
			return err
		}
	}
	bind(filepath.Join(dir, "ca.pem"), inDir+"/ca.pem")
	bind(bundleFile, inDir+"/ca-bundle.pem")

	// A BuildKit container starts its build steps with its own runc. Put
	// this wrapper in front of that runc too.
	if isFileInRoot(root, buildkitRunc) {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		bind(self, buildkitWrap)
	}

	proc, _ := spec["process"].(map[string]any)
	if proc == nil {
		proc = map[string]any{}
		spec["process"] = proc
	}
	remap, err := repointCAVars(proc, root, bundle, ca, bind)
	if err != nil {
		return err
	}
	addTrustEnv(proc)
	spec["mounts"] = mounts
	if err := writeJSON(cfgPath, spec); err != nil {
		return err
	}
	return saveState(id, remap)
}

// loadCA finds the PMG CA files. Only certificates may reach a container,
// so a file that holds a private key is an error.
func loadCA() (string, []byte, error) {
	for _, d := range caDirs {
		ca, err := os.ReadFile(filepath.Join(d, "ca.pem"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		bundle, err := os.ReadFile(filepath.Join(d, "ca-bundle.pem"))
		if err != nil {
			return "", nil, err
		}
		if !certsOnly(ca) || !certsOnly(bundle) {
			return "", nil, fmt.Errorf("%s holds data that is not a certificate", d)
		}
		return d, ca, nil
	}
	return "", nil, errors.New("no PMG CA files")
}

func certsOnly(pem []byte) bool {
	return bytes.Contains(pem, []byte("-----BEGIN CERTIFICATE-----")) && !bytes.Contains(pem, []byte("PRIVATE KEY"))
}

func imageBundle(root string) []byte {
	for _, p := range systemBundles {
		if own := imageFile(root, p); own != nil {
			return own
		}
	}
	return nil
}

// imageFile returns file p of the image. It returns nil when the file is
// missing, empty or not readable.
func imageFile(root, p string) []byte {
	own, err := readInRoot(root, p)
	if err != nil || len(bytes.TrimSpace(own)) == 0 {
		return nil
	}
	return own
}

func merge(own, ca []byte) []byte {
	out := append([]byte{}, own...)
	if !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	return append(out, ca...)
}

// repointCAVars handles a CA variable that the image sets itself, such as
// CURL_CA_BUNDLE=/cacert.pem. The variable then names a copy of that file
// with the PMG CA added. It maps the old entry of each variable that it
// changed to the new entry.
func repointCAVars(proc map[string]any, root, bundle string, ca []byte, bind func(src, dst string)) (map[string]string, error) {
	env, _ := proc["env"].([]any)
	remap := map[string]string{}
	for i, e := range env {
		s, _ := e.(string)
		k, v, ok := strings.Cut(s, "=")
		if !ok || !caVars[k] || !filepath.IsAbs(v) || strings.HasPrefix(v, inDir+"/") {
			continue
		}
		own := imageFile(root, v)
		if own == nil {
			continue
		}
		src := filepath.Join(bundle, "pmg-var-"+k+".pem")
		if err := writeFile(src, merge(own, ca), 0o644); err != nil {
			return nil, err
		}
		dst := inDir + "/vars/" + k + ".pem"
		bind(src, dst)
		env[i] = k + "=" + dst
		remap[s] = k + "=" + dst
	}
	return remap, nil
}

// addTrustEnv adds the trust variables. A variable that the process sets
// keeps its value.
func addTrustEnv(proc map[string]any) {
	env, _ := proc["env"].([]any)
	have := map[string]bool{}
	for _, e := range env {
		if s, ok := e.(string); ok {
			k, _, _ := strings.Cut(s, "=")
			have[k] = true
		}
	}
	for _, kv := range []string{
		"NODE_EXTRA_CA_CERTS=" + inDir + "/ca.pem",
		"REQUESTS_CA_BUNDLE=" + inDir + "/ca-bundle.pem",
		"PIP_CERT=" + inDir + "/ca-bundle.pem",
		"SSL_CERT_FILE=" + inDir + "/ca-bundle.pem",
		"UV_NATIVE_TLS=1",
	} {
		k, _, _ := strings.Cut(kv, "=")
		if !have[k] {
			env = append(env, kv)
		}
	}
	proc["env"] = env
}

// injectExec gives a "runc exec" process the trust variables. It changes
// only a process of a container that inject set up, because only that
// container has the CA files.
func injectExec(processFile, id string) error {
	remap, err := loadState(id)
	if err != nil {
		return err
	}
	proc, err := readJSON(processFile)
	if err != nil {
		return err
	}
	env, _ := proc["env"].([]any)
	for i, e := range env {
		if s, ok := e.(string); ok {
			if n, ok := remap[s]; ok {
				env[i] = n
			}
		}
	}
	addTrustEnv(proc)
	return writeJSON(processFile, proc)
}

func statePath(id string) string {
	return filepath.Join(stateDir, filepath.Base(id)+".json")
}

func saveState(id string, remap map[string]string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(remap)
	if err != nil {
		return err
	}
	return writeFile(statePath(id), raw, 0o600)
}

func loadState(id string) (map[string]string, error) {
	raw, err := os.ReadFile(statePath(id))
	if err != nil {
		return nil, err
	}
	remap := map[string]string{}
	if err := json.Unmarshal(raw, &remap); err != nil {
		return nil, err
	}
	return remap, nil
}

// openInRoot opens a regular file at path p inside root. The kernel resolves
// every symbolic link and ".." inside root, so an image cannot make the
// wrapper read a file of the runner. The file is first opened with O_PATH,
// so a FIFO or a device node is never opened.
func openInRoot(root, p string) (*os.File, error) {
	dirfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	defer closeOrLog(root, func() error { return unix.Close(dirfd) })
	fd, err := unix.Openat2(dirfd, p, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: p, Err: err}
	}
	defer closeOrLog(p, func() error { return unix.Close(fd) })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: p, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	return os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func readInRoot(root, p string) ([]byte, error) {
	f, err := openInRoot(root, p)
	if err != nil {
		return nil, err
	}
	defer closeOrLog(p, f.Close)
	data, err := io.ReadAll(io.LimitReader(f, maxCAFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCAFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, maxCAFile)
	}
	return data, nil
}

func isFileInRoot(root, p string) bool {
	f, err := openInRoot(root, p)
	if err != nil {
		return false
	}
	closeOrLog(p, f.Close)
	return true
}

// closeOrLog closes a file that the wrapper only read. A failed close loses
// no data, so the wrapper logs the error and continues.
func closeOrLog(name string, closeFn func() error) {
	if err := closeFn(); err != nil {
		logf("close %s: %v", name, err)
	}
}

// devIsTmpfs tells if /dev is a tmpfs of the container. The mount points of
// the CA files go in /dev. On a bind of another /dev, such as -v /dev:/dev,
// they would stay in the file system of that /dev.
func devIsTmpfs(mounts []any) bool {
	tmpfs := false
	for _, m := range mounts {
		if mm, ok := m.(map[string]any); ok && mm["destination"] == "/dev" {
			tmpfs = mm["type"] == "tmpfs"
		}
	}
	return tmpfs
}

func readJSON(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

// writeJSON replaces the file in one step and keeps its mode.
func writeJSON(path string, v any) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return writeFile(path, out.Bytes(), st.Mode().Perm())
}

// writeFile writes a temporary file in the same directory and renames it, so
// a reader sees the old file or the full new file.
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pmg-runc-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	err = errors.Join(err, tmp.Close())
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(tmp.Name()))
	}
	return nil
}

// logf writes to the log file. A BuildKit container has no log file, so the
// wrapper then writes to stderr, which BuildKit keeps in its log.
func logf(format string, a ...any) {
	line := fmt.Sprintf("%s pmg-runc: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		f = os.Stderr
	}
	// The log is the last place to report an error. A failed write or close
	// has no other place to go.
	_, _ = f.WriteString(line)
	if f != os.Stderr {
		_ = f.Close()
	}
}

func exitf(format string, a ...any) {
	// The process exits next, so a failed write changes nothing.
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
