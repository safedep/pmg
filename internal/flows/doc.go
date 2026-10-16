// Package flows runs one package manager command under PMG. It starts the
// proxy, wraps the command, and reports at exit.
//
// The package imports internal/ui because the report at exit is terminal
// output. internal/proxyserver imports this package for the CA setup, the
// analyzer and the network decision log, not for output, and must not
// import internal/ui itself.
package flows
