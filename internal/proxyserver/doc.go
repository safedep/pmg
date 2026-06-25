// Package proxyserver implements the persistent proxy flow: running PMG as a
// long-lived MITM proxy server that many package-manager processes route through
// via environment variables, for non-interactive CI/CD use.
//
// It is a flow, not a proxy implementation. The actual MITM proxy lives in the
// `proxy` package; proxyserver wires that proxy together with the analyzer,
// interceptors, audit pipeline, and cloud sync, and manages the daemon lifecycle
// (start/stop/env/status) coordinated through an on-disk state file.
//
// # Boundary with internal/flows
//
// internal/flows owns the per-command flow, where PMG wraps a single package
// manager invocation (spawns it as a child, injects env, prompts on confirmation,
// reports at exit). proxyserver owns the persistent flow, where the proxy
// outlives any single invocation and is driven by separate `pmg proxy` commands
// across processes. The two share lower-level building blocks (CA setup in
// flows.SetupCACertificate, proxy env vars in packagemanager.EnvVarForProxy,
// cloud sync in audit.DrainToCloud) but differ in lifecycle and process model,
// so they are kept as separate flows rather than one. Some assembly (analyzer +
// cache wiring) is intentionally duplicated for the MVP rather than prematurely
// unified.
package proxyserver
