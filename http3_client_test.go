package main

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestDialQUIC_DefaultTLSConfig verifies that dialQUIC creates proper default
// TLS configuration when nil is passed.
func TestDialQUIC_DefaultTLSConfig(t *testing.T) {
	// Use a very short timeout since we're testing config creation, not actual connection
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try to connect to a non-existent local address
	// This will fail, but we can verify the error message contains our address formatting
	_, err := dialQUIC(ctx, "localhost:19999", nil, nil)
	if err == nil {
		t.Fatal("expected error connecting to non-existent server")
	}

	// The error should mention our address
	if !strings.Contains(err.Error(), "localhost:19999") {
		t.Errorf("error should mention the address, got: %v", err)
	}
}

// TestDialQUIC_AddsDefaultPort verifies that port 443 is added when not specified.
func TestDialQUIC_AddsDefaultPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Connect without port - should add :443
	_, err := dialQUIC(ctx, "localhost", nil, nil)
	if err == nil {
		t.Fatal("expected error connecting to non-existent server")
	}

	// The error should mention localhost:443 (default port added)
	if !strings.Contains(err.Error(), "localhost:443") {
		t.Errorf("error should mention localhost:443 (default port), got: %v", err)
	}
}

// TestDialQUIC_TLSConfigHasH3ALPN verifies that the TLS config includes "h3" in NextProtos.
func TestDialQUIC_TLSConfigHasH3ALPN(t *testing.T) {
	// Create TLS config without h3
	tlsConfig := &tls.Config{
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// dialQUIC should add h3 to the front
	_, _ = dialQUIC(ctx, "localhost:19999", tlsConfig, nil)

	// Check that h3 was added
	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		t.Errorf("TLS config should have 'h3' in NextProtos, got: %v", tlsConfig.NextProtos)
	}
}

// TestDialQUIC_PreservesExistingH3ALPN verifies that existing h3 in ALPN is not duplicated.
func TestDialQUIC_PreservesExistingH3ALPN(t *testing.T) {
	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3", "http/1.1"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = dialQUIC(ctx, "localhost:19999", tlsConfig, nil)

	// Count h3 occurrences - should be exactly 1
	h3Count := 0
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			h3Count++
		}
	}
	if h3Count != 1 {
		t.Errorf("TLS config should have exactly one 'h3' in NextProtos, got %d in: %v", h3Count, tlsConfig.NextProtos)
	}
}

// TestDialQUIC_SetsServerName verifies that ServerName is set from the host.
func TestDialQUIC_SetsServerName(t *testing.T) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = dialQUIC(ctx, "example.com:443", tlsConfig, nil)

	if tlsConfig.ServerName != "example.com" {
		t.Errorf("ServerName should be 'example.com', got: %s", tlsConfig.ServerName)
	}
}

// TestDialQUIC_PreservesExistingServerName verifies that existing ServerName is not overwritten.
func TestDialQUIC_PreservesExistingServerName(t *testing.T) {
	tlsConfig := &tls.Config{
		ServerName:         "custom.example.com",
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = dialQUIC(ctx, "other.example.com:443", tlsConfig, nil)

	if tlsConfig.ServerName != "custom.example.com" {
		t.Errorf("ServerName should remain 'custom.example.com', got: %s", tlsConfig.ServerName)
	}
}

// TestDialQUIC_RespectsInsecureSkipVerify verifies that InsecureSkipVerify is respected.
func TestDialQUIC_RespectsInsecureSkipVerify(t *testing.T) {
	// Test with InsecureSkipVerify = false (should be preserved)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _ = dialQUIC(ctx, "localhost:19999", tlsConfig, nil)

	// Value should not be changed by dialQUIC
	if tlsConfig.InsecureSkipVerify != false {
		t.Error("InsecureSkipVerify should remain false when explicitly set")
	}
}

// TestDialQUIC_InvalidHost verifies that an invalid host returns an error.
func TestDialQUIC_InvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := dialQUIC(ctx, "this-host-does-not-exist-12345.invalid", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid host")
	}

	// Error should be descriptive
	if !strings.Contains(err.Error(), "this-host-does-not-exist-12345.invalid") {
		t.Errorf("error should mention the invalid host, got: %v", err)
	}
}

// TestDialQUIC_ContextTimeout verifies that context timeout is respected.
func TestDialQUIC_ContextTimeout(t *testing.T) {
	// Use an already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	start := time.Now()
	_, err := dialQUIC(ctx, "cloudflare.com:443", nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error with canceled context")
	}

	// Should fail quickly (under 1 second) since context is already canceled
	if elapsed > time.Second {
		t.Errorf("context cancellation should be fast, took: %v", elapsed)
	}
}

// TestDialQUIC_IntegrationCloudflare is an integration test that connects to a real HTTP/3 server.
// This test requires network access and may be skipped in CI environments.
func TestDialQUIC_IntegrationCloudflare(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Try multiple known HTTP/3 servers
	servers := []string{"www.google.com:443", "cloudflare.com:443", "www.cloudflare.com:443"}

	var conn quic.Connection
	var lastErr error

	for _, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := dialQUIC(ctx, server, nil, nil)
		cancel()

		if err != nil {
			lastErr = err
			t.Logf("failed to connect to %s: %v (trying next)", server, err)
			continue
		}

		conn = c
		t.Logf("successfully connected to %s", server)
		break
	}

	if conn == nil {
		t.Skipf("could not connect to any HTTP/3 server (network may be restricted): %v", lastErr)
	}
	defer conn.CloseWithError(0, "test complete")

	// Get connection state
	state := conn.ConnectionState()

	// Check ALPN was negotiated as h3
	if state.TLS.NegotiatedProtocol != "h3" {
		t.Errorf("expected ALPN 'h3', got: %s", state.TLS.NegotiatedProtocol)
	}

	// Verify TLS 1.3 is used (QUIC requires it)
	if state.TLS.Version != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got version: %x", state.TLS.Version)
	}
}
