package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/proxy"
	"github.com/safedep/pmg/proxy/certmanager"
)

const (
	listenAddr     = "127.0.0.1:8888"
	connectTimeout = 30 * time.Second
	requestTimeout = 5 * time.Minute
)

func main() {
	log.InitZapLogger("proxy-example", "dev")

	fmt.Println("Generating CA certificate...")

	caConfig := certmanager.DefaultCertManagerConfig()
	caCert, err := certmanager.GenerateCA(caConfig)
	if err != nil {
		log.Fatalf("Failed to generate CA: %v", err)
	}

	// Save CA cert for use with clients
	if err := os.WriteFile("ca-cert.pem", caCert.Certificate, 0644); err != nil {
		log.Fatalf("Failed to save CA cert: %v", err)
	}

	fmt.Println("✓ CA certificate saved to ca-cert.pem")
	fmt.Println()
	fmt.Println("To trust this CA:")
	fmt.Println("  Node.js: export NODE_EXTRA_CA_CERTS=./ca-cert.pem")
	fmt.Println("  Python:  export SSL_CERT_FILE=./ca-cert.pem")
	fmt.Println("  System:  Add ca-cert.pem to your OS trust store")
	fmt.Println()

	// Create certificate manager with CA certificate for use with proxy
	certMgr, err := certmanager.NewCertificateManagerWithCA(caCert, caConfig)
	if err != nil {
		log.Fatalf("Failed to create cert manager: %v", err)
	}

	malysisQueryAnalyzer, err := analyzer.NewMalysisQueryAnalyzer(analyzer.MalysisQueryAnalyzerConfig{})
	if err != nil {
		fmt.Println("failed to initialise malysis query analyser: ", err)
		os.Exit(0)
	}

	// Create proxy with certificate manager and logging interceptor
	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:     listenAddr,
		CertManager:    certMgr,
		EnableMITM:     true,
		Interceptors:   []proxy.Interceptor{newMalysisInterceptor(malysisQueryAnalyzer)},
		ConnectTimeout: connectTimeout,
		RequestTimeout: requestTimeout,
	}

	proxyServer, err := proxy.NewProxyServer(proxyConfig)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Start proxy
	if err := proxyServer.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	fmt.Printf("Proxy listening on %s\n", proxyServer.Address())
	fmt.Printf("Configure clients with: export HTTPS_PROXY=http://%s\n", listenAddr)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Wait for interrupt signal to gracefully shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	fmt.Println("\nShutting down proxy...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := proxyServer.Stop(ctx); err != nil {
		log.Errorf("Error during shutdown: %v", err)
	}

	fmt.Println("Proxy stopped")
}
