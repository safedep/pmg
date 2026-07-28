# eBPF Enforcement POC: Setup Guide

This guide sets up the POC on a new Linux machine.

The POC makes package manager traffic go through the PMG proxy.
It does this in the Linux kernel.
The package manager does not need any configuration.
It cannot avoid the proxy.

Follow the steps in order.
Each step has one task.

---

## Before You Start

You need a Linux machine.
It must have these things:

| Item | Required value | How to check |
|---|---|---|
| Kernel | 5.8 or later | `uname -r` |
| cgroup v2 | mounted | `stat -fc %T /sys/fs/cgroup` shows `cgroup2fs` |
| BTF | present | `ls /sys/kernel/btf/vmlinux` |
| Root access | yes | `sudo -v` |

macOS does not work.
eBPF runs only in the Linux kernel.
Use a Linux virtual machine.

---

## Step 1. Check the Machine

Run this command:

```bash
uname -r
stat -fc %T /sys/fs/cgroup
ls /sys/kernel/btf/vmlinux
```

You must see a kernel of 5.8 or later.
You must see `cgroup2fs`.
You must see the BTF file.

If one item is missing, stop.
The POC does not work on this machine.

---

## Step 2. Install the Build Tools

Run this command:

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev git
```

`build-essential` gives the C standard library headers.
PMG needs them because it builds a part that uses C.
`clang` compiles the C code to eBPF bytecode.
`libbpf-dev` gives the header files that the C code includes.

Do not skip `build-essential`.
A machine can have `gcc` but not these headers.
The build then fails with messages such as `fatal error: errno.h: No such file or directory`.

---

## Step 3. Install Go

Check if Go is present:

```bash
go version
```

You need Go 1.25 or later.

If Go is missing, install it:

```bash
sudo apt-get install -y golang-go
```

If the version is too old, download Go from https://go.dev/dl/ instead.

---

## Step 4. Install Node.js and npm

Run this command:

```bash
sudo apt-get install -y nodejs npm
```

npm is needed only for the test in Step 14.
PMG does not change any npm configuration.

Use the npm from `apt`.
That build reads the system trust store, so the test needs no extra setup.

---

## Step 5. Get the Code

Run this command:

```bash
cd ~
git clone https://github.com/safedep/pmg.git
cd ~/pmg
git checkout ebpf-poc
```

Clone into your home directory.
The later steps use the path `~/pmg`.

---

## Step 6. Set the Architecture Path

This step is only for x86-64 machines.
Skip this step on ARM64 machines.

Find your architecture:

```bash
uname -m
```

If the result is `aarch64`, skip this step.

If the result is `x86_64`, edit `ebpf-poc/main.go`.
Find the first line.
Change `aarch64-linux-gnu` to `x86_64-linux-gnu`.

The line must look like this:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -type target bpf connect.c -- -I/usr/include/x86_64-linux-gnu
```

The compiler needs this path.
It cannot find the kernel headers without it.

---

## Step 7. Build PMG

Run these commands from the repository root:

Build first:

```bash
cd ~/pmg
go build -o /tmp/pmg .
```

Check the build before you install it:

```bash
/tmp/pmg version
```

You must see the PMG banner and a version number.

If you see a list of flags such as `-exempt-uid`, you built the wrong program.
You were in the `ebpf-poc` directory.
Run `cd ~/pmg` and build again.

Now install it:

```bash
sudo cp /tmp/pmg /usr/local/bin/pmg
```

Always check before you copy.
A failed build does not create the file.
The copy then installs an old file, or it fails with `Text file busy`.

---

## Step 8. Build the Hook Agent

Run these commands:

```bash
cd ~/pmg/ebpf-poc
export GOWORK=off
go generate
go build -o pmgwatch .
```

`GOWORK=off` is required.
The repository has a `go.work` file.
That file does not list this module.
Go refuses to build without this setting.

Check the result:

```bash
./pmgwatch ca --help
```

You must see the CA usage text.

---

## Step 9. Create the Proxy User

Run these commands:

```bash
sudo useradd --system --create-home \
     --home-dir /var/lib/pmg-proxy \
     --shell /usr/sbin/nologin pmg-proxy
```

This is the only command you need.
The proxy creates its own state directory on first start.

The proxy runs as this user.
The kernel hook uses this user as the exemption key.
The hook does not redirect traffic from this user.

This user must be separate.
It must not be the user that runs npm.
If both are the same user, the hook exempts npm as well.
Then nothing is enforced.

---

## Step 10. Create a Test User

Run this command:

```bash
sudo useradd -m -s /bin/bash testuser
```

This user runs npm in the test.
This user has no special rights.

---

## Step 11. Install the Certificate

Run these commands:

```bash
cd ~/pmg/ebpf-poc
sudo ./pmgwatch ca install
sudo ./pmgwatch ca status
```

The status output must show four `PASS` lines.

The proxy must be stopped during this step.
The proxy reads the certificate when it starts.

This command does three things.
It creates a certificate that does not change.
It gives the private key to the proxy user only.
It adds the certificate to the system trust store.

The system trust store makes the certificate valid for every user.
Every program that reads the system trust store now trusts the proxy.

---

## Step 11a. Tools That Ignore the System Trust Store

Some programs do not read the system trust store.
They carry their own list of certificates inside the program file.

| Program | Reads the system trust store |
|---|---|
| curl, wget, git, Go | Yes |
| npm from `apt install nodejs` | Yes |
| pip from `apt install python3-pip` | Yes |
| **npm from nodejs.org, nvm, or Docker** | **No** |
| **bun** | **No** |
| **uv** | **No** |

If you use a program from the second group, configure it yourself.
Point it at the file that Step 11 wrote:

```
/var/lib/pmg-ebpf-poc/pmg-ca-bundle.pem
```

Use one of these settings:

| Program | Setting |
|---|---|
| npm | `npm config set cafile /var/lib/pmg-ebpf-poc/pmg-ca-bundle.pem` |
| Node, bun | `NODE_EXTRA_CA_CERTS=/var/lib/pmg-ebpf-poc/pmg-ca-bundle.pem` |
| uv | `native-tls = true` in `/etc/uv/uv.toml` |
| pip | `cert = /var/lib/pmg-ebpf-poc/pmg-ca-bundle.pem` in `/etc/pip.conf` |

On this guide's Ubuntu machine, npm comes from `apt`.
It reads the system trust store.
You do not need this step.

---

## Step 12. Start the Proxy

Run this command:

```bash
export STATE=/var/lib/pmg-proxy/state/proxy.json

sudo -u pmg-proxy env HOME=/var/lib/pmg-proxy \
     pmg proxy start --daemon --transparent --state $STATE
```

The command prints the address and the process number.

`--transparent` is required.
Without it the proxy refuses redirected connections.

---

## Step 13. Start the Hook

Open a second terminal.
Run these commands:

```bash
cd ~/pmg/ebpf-poc
sudo ./pmgwatch -proxy-state /var/lib/pmg-proxy/state/proxy.json -tcp-only
```

You must see this output:

```
Proxy daemon: pid NNNNN, addr 127.0.0.1:NNNNN, uid NNN
Redirect target: 127.0.0.1:NNNNN
Exempt uids: NNN
Attached to /sys/fs/cgroup. Ctrl+C to exit.
ACTION          COMMAND    UID    PID    DESTINATION    PROTO
```

The numbers differ on every machine.
The port is chosen at random.
The user id depends on what the system assigned to `pmg-proxy`.

The exempt user id must match the proxy.
The tool reads both from the proxy state file, so they cannot disagree.

This terminal stays open.
It shows one line for each connection.

---

## Step 14. Test It

Open a third terminal.
Log in as the test user:

```bash
sudo su - testuser
```

Run these commands:

```bash
rm -rf ~/.npm/_cacache
mkdir -p ~/t && cd ~/t

npm i --no-audit --no-fund --fetch-retries=0 is-odd
npm i --no-audit --no-fund --fetch-retries=0 safedep-test-pkg
```

The first command must succeed.
You see `added 2 packages`.

The second command must fail.
You see `npm ERR! code E403`.
PMG blocked this package.

In the second terminal you see lines like this:

```
REDIRECT      npm i is-odd    1000  104.16.1.34:443   TCP
skip/exempt   pmg              500  104.16.1.34:443   TCP
```

The user ids and the address differ on your machine.
The first line is `testuser`. The second line is `pmg-proxy`.

`REDIRECT` means the hook captured npm.
`skip/exempt` means the proxy fetched the package.
The proxy is not redirected. This prevents a loop.

There is no proxy setting in the environment.
This is the purpose of the POC.

---

## Step 15. See the Block Message

Run this command as the test user.
Note the `-4` flag. It is required. The reason follows below.

```bash
curl -4 -s https://registry.npmjs.org/safedep-test-pkg/-/safedep-test-pkg-0.1.3.tgz
```

You see the reason for the block:

```
Malicious package blocked: npm/safedep-test-pkg@0.1.3
Reason: ...
Reference: https://app.safedep.io/community/malysis/...
```

### Why `-4` is required

The hook watches IPv4 only.
On a machine with IPv6, curl prefers IPv6.
The connection then never reaches the hook.

Without `-4` you get the real package file, not the block message:

```
curl        remote=2606:4700:91b3:...   no hook event, real file
curl -4     remote=104.16.7.34          REDIRECT logged, block message
```

This is a real gap, not a problem with the test.
Any program that prefers IPv6 avoids the proxy on this machine.
See Current Limits at the end of this guide.

---

## Step 16. Stop Everything

Press `Ctrl+C` in the second terminal.
This stops the hook.

Then run this command in the first terminal:

```bash
sudo -u pmg-proxy env HOME=/var/lib/pmg-proxy \
     pmg proxy stop --state $STATE --fail-on-violation
echo "exit: $?"
```

You see the number of blocked packages.
The exit code is 1 if a package was blocked.
A build system uses this exit code to fail the job.

---

## Step 17. Remove Everything

Run these commands:

```bash
cd ~/pmg/ebpf-poc
sudo pkill -INT -f pmgwatch
sudo -u pmg-proxy env HOME=/var/lib/pmg-proxy pmg proxy stop --state $STATE
sudo ./pmgwatch ca remove
```

Stop the proxy before you run `ca remove`.
The command refuses to run while the proxy is running.

`ca remove` takes the certificate out of the system trust store.
It then deletes the certificate files and the public bundle.

Check that the certificate is gone:

```bash
grep -c "SafeDep" /etc/ssl/certs/ca-certificates.crt
```

The result must be `0`.

Do not use `ls /etc/ssl/certs | grep pmg` for this check.
That command can still show two links after a correct removal.
The links point to a file that no longer exists.
They do not grant trust.
The `grep` command above is the reliable check.

---

## Optional: Docker Containers

Skip this section if you do not use Docker.

The hook already sees traffic from containers.
Container processes belong to a cgroup under the same root.
The hook applies to them.

The problem is the address.
`127.0.0.1` inside a container is the container's own loopback.
The proxy is not there.
The connection is rewritten and then goes nowhere.

### The change

Bind the proxy to the Docker bridge address instead of loopback.

Find the bridge address:

```bash
ip -4 addr show docker0 | grep inet
```

The usual value is `172.17.0.1`.

Start the proxy on that address:

```bash
sudo -u pmg-proxy env HOME=/var/lib/pmg-proxy \
     pmg proxy start --daemon --transparent --host 172.17.0.1 --state $STATE
```

No other change is needed.
`pmgwatch` reads the address from the proxy state file.

This one address serves both worlds.
A container reaches the host at `172.17.0.1`.
The host also owns that address, so host programs still reach the proxy.

Do not use `--host 0.0.0.0`.
The state file would then hold `0.0.0.0`, which is not a valid destination.

### Test it

```bash
sudo docker run --rm curlimages/curl:latest \
     -4 -sS -m 20 -o /dev/null https://registry.npmjs.org/is-odd
echo "exit: $?"
```

Expect exit code `60`.
The hook log shows a `REDIRECT` line for the container.

### Read the result

| Proxy address | curl exit | Meaning |
|---|---|---|
| `127.0.0.1` | connection failed | The container never reached the proxy |
| `172.17.0.1` | `60` | The container reached the proxy and refused the certificate |

Exit code `60` means the certificate was not trusted.
This is the expected result.
The container has its own certificate list inside its own file system.
The system trust store of the host is not visible inside a container.

Exit code `60` is a success for the visibility layer.
The connection is now mediated.
It fails at trust, not at the address.

### To make a container succeed

The person who starts the container must pass the certificate in:

```bash
sudo docker run --rm \
     -v /var/lib/pmg-ebpf-poc/pmg-ca-bundle.pem:/etc/ssl/certs/ca-certificates.crt:ro \
     curlimages/curl:latest -4 -sS https://registry.npmjs.org/is-odd
```

There is no way to do this from the host.
A container cannot be given a certificate it was not started to accept.

### Limits

- Only the default bridge network works.
  Docker Compose and custom networks use other addresses such as `172.18.0.1`.
  One fixed address does not cover them.
- The proxy is no longer on loopback only.
  Anything that can reach `172.17.0.1` can use it.
  Use this on an isolated machine, or add a firewall rule.
- `docker pull` already worked before this change.
  The Docker daemon runs on the host, so the hook always saw it.

---

## Problems and Fixes

| Message | Cause | Fix |
|---|---|---|
| `./pmgwatch: command not found` | You are in the wrong directory | `cd ~/pmg/ebpf-poc` |
| `directory prefix . does not contain modules listed in go.work` | The workspace file hides this module | `export GOWORK=off` |
| `'asm/types.h' file not found` | Wrong architecture path | See Step 6 |
| `fatal error: errno.h: No such file or directory` | The C library headers are missing | `sudo apt-get install -y build-essential` |
| `Text file busy` | The proxy is running from that file | Stop the proxy, then copy again |
| `map create: operation not permitted` | You are not root | Use `sudo` |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | The program does not trust the certificate | Run `sudo ./pmgwatch ca status`. If it passes, the program ignores the system trust store. See Step 11a |
| `existing CA state was created with different options` | A previous setup used other options | Run `sudo ./pmgwatch ca remove` first |
| `proxy pid N is still running` | The proxy is running | Stop the proxy, then install the certificate |
| No events appear | npm used its local cache | `rm -rf ~/.npm/_cacache` |
| Strange `skip/loopback` lines | Two hooks are attached | `pgrep pmgwatch`, then stop the extra one |

---

## Important Rules

1. Install the certificate before you start the proxy.
   The proxy reads the certificate at start time.

2. Run only one `pmgwatch` at a time.
   Two hooks change the same address one after the other.
   The result is confusing.

3. Clear the npm cache before each test.
   A cached package does not use the network.
   The hook sees nothing.

4. The proxy user and the npm user must be different.
   The hook does not redirect the proxy user.

---

## Current Limits

The POC does not handle these cases:

- **IPv6.** The hook watches IPv4 only. A client that uses IPv6 is not seen and
  reaches the registry directly. This was measured on a dual stack machine:
  `curl` chose IPv6, produced no hook event, and downloaded a package that PMG
  blocks over IPv4. npm happened to choose IPv4, but that is luck, not design.
  Use `curl -4` when testing. Closing this needs a `cgroup/connect6` program.
- **Containers.** The hook sees container traffic, and the container can reach
  the proxy once it is bound to the Docker bridge address. See the Docker
  section above. The container still does not trust the certificate, so the
  request fails at TLS. That is accepted for now. Only the default bridge
  network is covered.
- **QUIC.** The hook does not block UDP port 443.
- **Programs with their own certificate list.** PMG adds the certificate to the
  system trust store only. It does not change the configuration of any program.
  Programs that ignore the system trust store need manual setup. See Step 11a.

The last item is a decision, not an oversight.
PMG owns the one mechanism that works for every user and every program that
reads it. Per program configuration is documented instead, because each
program keeps its certificate list in a different place and in a different
format.
