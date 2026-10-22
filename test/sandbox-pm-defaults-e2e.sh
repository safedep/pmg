#!/usr/bin/env bash
#
# Runs each package manager under its built-in sandbox profile in enforce
# mode and checks the default paths that the profile must allow or deny.
# The CI sandbox jobs run it on macOS (Seatbelt) and Linux (Bubblewrap,
# Landlock). It needs pmg, node with corepack, npm, uv, cargo and pip3 on
# PATH.
#
# Bubblewrap and Landlock cannot create a missing directory that a profile
# allows. A first run of the tool outside the sandbox creates it, so the
# script creates it on Linux. On macOS it does not, which proves that the
# sandboxed run creates it.

set -euo pipefail

OS=$(uname -s)

sandboxed() {
	pmg --sandbox --sandbox-enforce "$@"
}

linux_mkdir() {
	if [ "$OS" = Linux ]; then
		mkdir -p "$@"
	fi
}

# The work directory is under $HOME, not /tmp. The /tmp/** write rule of
# the profiles would hide a missing project rule.
workdir() {
	mktemp -d "$HOME/pmg-pm-defaults.XXXXXX"
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# Corepack downloads the pinned pnpm into ~/.cache/node/corepack. Before the
# pnpm profile allowed it, pnpm -v failed with EPERM on mkdir.
test_corepack_pnpm() {
	echo "== corepack pnpm"
	local dir shims
	dir=$(workdir)
	shims="$dir/shims"
	mkdir "$shims" "$dir/app"
	corepack enable --install-directory "$shims" pnpm
	linux_mkdir "$HOME/.cache/node/corepack"
	cd "$dir/app"
	printf '{"name":"app","version":"1.0.0","packageManager":"pnpm@9.15.9"}\n' >package.json

	# PMG prints its own summary after the output of pnpm.
	PATH="$shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 sandboxed pnpm --version | tee version.txt
	grep -qx "9.15.9" version.txt || fail "corepack pnpm did not print version 9.15.9"
	test -d "$HOME/.cache/node/corepack/v1/pnpm/9.15.9" || fail "corepack did not cache pnpm 9.15.9"
	cd - >/dev/null
	rm -rf "$dir"
}

# Corepack keeps its cache in $XDG_CACHE_HOME/node/corepack when the variable
# is set. The profile rule ${XDG_CACHE_HOME}/node/corepack/** must follow it.
# A value of $HOME must not widen the rule to all of HOME, so pmg uses the
# default and the write to $HOME/node is denied.
test_corepack_xdg_cache() {
	echo "== corepack with XDG_CACHE_HOME"
	local dir shims cache
	dir=$(workdir)
	shims="$dir/shims"
	cache="$dir/xdg-cache"
	mkdir "$shims" "$dir/app"
	corepack enable --install-directory "$shims" pnpm
	linux_mkdir "$cache/node/corepack"
	cd "$dir/app"
	printf '{"name":"app","version":"1.0.0","packageManager":"pnpm@9.15.9"}\n' >package.json

	PATH="$shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 XDG_CACHE_HOME="$cache" \
		sandboxed pnpm --version | tee version.txt
	grep -qx "9.15.9" version.txt || fail "corepack pnpm did not run with XDG_CACHE_HOME=$cache"
	test -d "$cache/node/corepack/v1/pnpm/9.15.9" || fail "corepack did not cache pnpm in $cache"

	if PATH="$shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 XDG_CACHE_HOME="$HOME" \
		sandboxed pnpm --version; then
		fail "XDG_CACHE_HOME=$HOME widened the corepack rule to HOME"
	fi
	test ! -e "$HOME/node/corepack/v1/pnpm/9.15.9" || fail "corepack wrote $HOME/node/corepack"
	cd - >/dev/null
	rm -rf "$dir"
}

# On macOS a /** write rule also allows writes to the directory itself, so
# mkdir of that directory works. Only a directory may be created there. A
# symlink there would send every later write to dir/**, also from a tool
# that runs outside the sandbox, to where the link points. The test also
# makes the link in the project and renames it into place.
# Bubblewrap and Landlock do not allow a missing directory, so the test runs
# on macOS only.
test_parent_dir_symlink() {
	echo "== parent of a /** write rule"
	if [ "$OS" != Darwin ]; then
		echo "skip: macOS only"
		return
	fi
	local dir
	dir=$(workdir)
	mkdir "$dir/app" "$dir/elsewhere"
	cd "$dir/app"

	if pmg sandbox exec --sandbox-allow "write=$dir/cache/**" -- ln -s "$dir/elsewhere" "$dir/cache"; then
		fail "the sandbox let a process create a symlink at the parent of a /** write rule"
	fi
	ln -s "$dir/elsewhere" link
	if pmg sandbox exec --sandbox-allow "write=$dir/cache/**" -- mv link "$dir/cache"; then
		fail "the sandbox let a process rename a symlink onto the parent of a /** write rule"
	fi
	test -L link || fail "the symlink left the project"
	test ! -L "$dir/cache" || fail "a symlink exists at $dir/cache"

	pmg sandbox exec --sandbox-allow "write=$dir/cache/**" -- mkdir "$dir/cache" ||
		fail "the sandbox denied mkdir of the parent of a /** write rule"
	test -d "$dir/cache" || fail "mkdir did not create $dir/cache"
	cd - >/dev/null
	rm -rf "$dir"
}

# Without PNPM_HOME, pnpm keeps its store in ~/Library/pnpm/store on macOS
# and in ~/.local/share/pnpm/store on Linux. pnpm/action-setup sets
# PNPM_HOME, so the test removes it. On Linux the profile cannot allow the
# _tmp_* directory that pnpm links a test file into, so pnpm can keep the
# store in the project. The test accepts either store on Linux.
test_pnpm_default_store() {
	echo "== pnpm default store"
	local dir store
	if [ "$OS" = Darwin ]; then
		store="$HOME/Library/pnpm/store"
	else
		store="$HOME/.local/share/pnpm/store"
	fi
	linux_mkdir "$store" "$HOME/.local/state/pnpm"
	dir=$(workdir)
	cd "$dir"
	npm init -y >/dev/null

	env -u PNPM_HOME -u npm_config_store_dir -u NPM_CONFIG_STORE_DIR \
		pmg --sandbox --sandbox-enforce pnpm add lodash@4.17.21
	test -d node_modules/lodash || fail "pnpm did not install lodash"
	if [ "$OS" = Linux ] && [ -d .pnpm-store ]; then
		store="$dir/.pnpm-store"
	fi
	if ! find "$store" -mindepth 1 -maxdepth 1 -name 'v*' 2>/dev/null | grep -q .; then
		echo "pnpm store path: $(env -u PNPM_HOME pnpm store path 2>&1)"
		echo "pnpm store-dir: $(env -u PNPM_HOME pnpm config get store-dir 2>&1)"
		echo "stores under HOME:"
		find "$HOME" -maxdepth 6 -type d -name 'v1[0-9]' -path '*store*' -not -path '*/node_modules/*' 2>/dev/null
		fail "pnpm did not use the store at $store"
	fi
	cd - >/dev/null
	rm -rf "$dir"
}

# Yarn 4 keeps its global cache in ~/.yarn/berry/cache. Corepack caches the
# pinned Yarn in ~/.cache/node/corepack.
test_yarn_berry() {
	echo "== yarn berry"
	local dir shims
	dir=$(workdir)
	shims="$dir/shims"
	mkdir "$shims" "$dir/app"
	corepack enable --install-directory "$shims" yarn
	linux_mkdir "$HOME/.cache/node/corepack" "$HOME/.yarn/berry"
	cd "$dir/app"
	printf '{"name":"app","version":"1.0.0","packageManager":"yarn@4.16.0"}\n' >package.json

	PATH="$shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 YARN_ENABLE_TELEMETRY=0 \
		YARN_ENABLE_IMMUTABLE_INSTALLS=false sandboxed yarn add lodash@4.17.21
	test -f yarn.lock || fail "yarn did not write yarn.lock"
	find "$HOME/.yarn/berry/cache" -name 'lodash-*' | grep -q . || fail "yarn did not use the global cache"
	cd - >/dev/null
	rm -rf "$dir"
}

# node-gyp downloads the Node.js headers into its cache before it builds a
# native addon.
test_node_gyp_cache() {
	echo "== node-gyp cache"
	local dir cache
	if [ "$OS" = Darwin ]; then
		cache="$HOME/Library/Caches/node-gyp"
	else
		cache="$HOME/.cache/node-gyp"
	fi
	linux_mkdir "$cache"
	dir=$(workdir)
	cd "$dir"
	npm init -y >/dev/null

	sandboxed npm exec --yes -- node-gyp@11.2.0 install
	test -f "$cache/$(node -p process.versions.node)/include/node/node.h" || fail "node-gyp did not cache the headers in $cache"
	cd - >/dev/null
	rm -rf "$dir"
}

# uv sync downloads a managed Python into ~/.local/share/uv/python when no
# installed Python matches the project.
test_uv_managed_python() {
	echo "== uv managed python"
	local dir
	linux_mkdir "$HOME/.local/share/uv/python" "$HOME/.cache/uv"
	dir=$(workdir)
	cd "$dir"
	cat >pyproject.toml <<'EOF'
[project]
name = "pmg-uv-python"
version = "0.0.0"
requires-python = "==3.11.*"
dependencies = []
EOF

	env -u UV_CACHE_DIR -u UV_PYTHON_INSTALL_DIR -u UV_PYTHON UV_PYTHON_PREFERENCE=only-managed \
		pmg --sandbox --sandbox-enforce uv sync
	test -x .venv/bin/python || fail "uv did not create the virtualenv"
	find "$HOME/.local/share/uv/python" -mindepth 1 -maxdepth 1 -name 'cpython-3.11*' | grep -q . ||
		fail "uv did not keep the managed Python in ~/.local/share/uv/python"
	cd - >/dev/null
	rm -rf "$dir"
}

# A build script must not read the registry token or write the cargo config.
# cargo itself must still build a crate with a crates.io dependency.
test_cargo_credentials() {
	echo "== cargo credentials and config"
	# The cargo profile sets network_via_proxy_only, and Bubblewrap does not
	# support it. pmg refuses to run cargo under Bubblewrap.
	if [ "${PMG_SANDBOX_DRIVER:-}" = bubblewrap ]; then
		echo "skip: Bubblewrap does not support the cargo profile"
		return 0
	fi
	local dir
	created=()
	# Each test runs in its own process, so the trap removes the files that
	# this test created also when a step fails.
	trap 'if [ "${#created[@]}" -gt 0 ]; then rm -f "${created[@]}"; fi' EXIT
	mkdir -p "$HOME/.cargo"
	if [ -e "$HOME/.cargo/credentials.toml" ]; then
		fail "the runner already has ~/.cargo/credentials.toml"
	fi
	printf '[registry]\ntoken = "pmg-e2e-canary"\n' >"$HOME/.cargo/credentials.toml"
	created+=("$HOME/.cargo/credentials.toml")
	if [ ! -e "$HOME/.cargo/config.toml" ]; then
		: >"$HOME/.cargo/config.toml"
		created+=("$HOME/.cargo/config.toml")
	fi
	dir=$(workdir)
	cd "$dir"
	cat >Cargo.toml <<'EOF'
[package]
name = "pmg-cargo-defaults"
version = "0.0.0"
edition = "2021"

[dependencies]
itoa = "=1.0.11"
EOF
	mkdir src
	echo 'fn main() { println!("{}", itoa::Buffer::new().format(1)); }' >src/main.rs
	# Bubblewrap masks a denied file with /dev/null, so a read can succeed
	# with no data. The check looks for the token, not for an error.
	cat >build.rs <<'EOF'
use std::{env, fs, path::PathBuf};

fn main() {
    let cargo_home = PathBuf::from(env::var("HOME").unwrap()).join(".cargo");
    if let Ok(data) = fs::read_to_string(cargo_home.join("credentials.toml")) {
        if data.contains("pmg-e2e-canary") {
            panic!("build script read the token in ~/.cargo/credentials.toml");
        }
    }
    if fs::OpenOptions::new().append(true).open(cargo_home.join("config.toml")).is_ok() {
        panic!("build script opened ~/.cargo/config.toml for write");
    }
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let _ = fs::write(manifest_dir.join(".cargo").join("config.toml"), "");
}
EOF
	mkdir .cargo

	# Outside the sandbox the build script reads the token, so the build
	# fails. This proves that the sandboxed build below tests the deny rules.
	if cargo build --quiet 2>/dev/null; then
		fail "the build script passed outside the sandbox"
	fi
	# Without the lockfile, the sandboxed cargo resolves itoa against the
	# registry again, through the PMG proxy.
	rm -f Cargo.lock
	sandboxed cargo build
	# Bubblewrap applies a deny only to a file that exists, so it lets the
	# build script create the project config.
	if [ "${PMG_SANDBOX_DRIVER:-}" != bubblewrap ] && [ -e .cargo/config.toml ]; then
		fail "the build script created .cargo/config.toml in the project"
	fi
	cd - >/dev/null
	rm -rf "$dir"
}

# The pip profile does not allow writes to the user site. The pip-user
# preset allows them.
test_pip_user_site() {
	echo "== pip user site"
	local dir py user_site
	# pip3 and python3 can be different interpreters on a macOS runner. Take
	# the user site of the Python that pip3 runs on.
	py=python$(pip3 --version | sed -n 's/.*(python \([0-9.]*\)).*/\1/p')
	user_site=$("$py" -m site --user-site)
	linux_mkdir "$user_site"
	dir=$(workdir)
	cd "$dir"
	export PIP_BREAK_SYSTEM_PACKAGES=1 PIP_DISABLE_PIP_VERSION_CHECK=1

	# --ignore-installed makes pip write six even when the system site has it.
	if sandboxed pip3 install --user --ignore-installed --no-deps six==1.16.0; then
		fail "pip3 install --user passed without the pip-user preset"
	fi
	test ! -e "$user_site/six.py" || fail "six.py is in the user site without the pip-user preset"

	sandboxed --sandbox-allow preset=pip-user pip3 install --user --ignore-installed --no-deps six==1.16.0
	test -f "$user_site/six.py" || fail "pip3 did not install six into $user_site"
	"$py" -m pip uninstall --yes six
	unset PIP_BREAK_SYSTEM_PACKAGES PIP_DISABLE_PIP_VERSION_CHECK
	cd - >/dev/null
	rm -rf "$dir"
}

tests=(
	test_corepack_pnpm
	test_corepack_xdg_cache
	test_pnpm_default_store
	test_yarn_berry
	test_node_gyp_cache
	test_uv_managed_python
	test_cargo_credentials
	test_pip_user_site
	test_parent_dir_symlink
)

# With arguments, the script runs the named tests in this process. Without
# them, it runs each test in its own process, so one failure does not hide
# the result of the other tests.
if [ "$#" -gt 0 ]; then
	for t in "$@"; do
		"$t"
	done
	exit 0
fi

failed=()
for t in "${tests[@]}"; do
	"$0" "$t" || failed+=("$t")
done
if [ "${#failed[@]}" -gt 0 ]; then
	fail "these tests failed: ${failed[*]}"
fi
echo "All package manager default path tests passed"
