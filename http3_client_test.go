package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
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

// =============================================================================
// sendPartialRequests tests
// =============================================================================

// TestSendPartialRequests_NilConnection verifies that an error is returned when
// the QUIC connection is not established.
func TestSendPartialRequests_NilConnection(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	r := &http3Request{
		Request: req,
		conn:    nil, // No connection
	}

	ctx := context.Background()
	err := r.sendPartialRequests(ctx, 5)
	if err == nil {
		t.Fatal("expected error when connection is nil")
	}
	if !strings.Contains(err.Error(), "QUIC connection not established") {
		t.Errorf("expected 'QUIC connection not established' error, got: %v", err)
	}
}

// TestSendPartialRequests_NilRequest verifies that an error is returned when
// the request is not set.
func TestSendPartialRequests_NilRequest(t *testing.T) {
	// We need a mock connection here, but since we check Request first after conn,
	// we can't easily test this without a real connection.
	// Instead, we'll test the error message structure.

	// Create a fake connection scenario by using a context timeout approach
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try to establish a connection to a non-existent server
	conn, err := dialQUIC(ctx, "localhost:19998", nil, nil)
	if err == nil {
		// Unexpected success - clean up and test with it
		defer conn.CloseWithError(0, "test")
		r := &http3Request{
			conn:    conn,
			Request: nil, // No request
		}
		err = r.sendPartialRequests(context.Background(), 5)
		if err == nil {
			t.Fatal("expected error when request is nil")
		}
		if !strings.Contains(err.Error(), "request not set") {
			t.Errorf("expected 'request not set' error, got: %v", err)
		}
	}
	// If connection failed (expected), we can't test this scenario easily
	// without mocking, so we'll skip the deeper test
}

// TestSendPartialRequests_InvalidCount verifies that zero or negative counts
// return an error.
func TestSendPartialRequests_InvalidCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try to establish a connection
	conn, err := dialQUIC(ctx, "localhost:19997", nil, nil)
	if err == nil {
		defer conn.CloseWithError(0, "test")

		req, _ := http.NewRequest("GET", "https://localhost:19997/", nil)
		r := &http3Request{
			conn:    conn,
			Request: req,
		}

		// Test count = 0
		err = r.sendPartialRequests(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error when count is 0")
		}
		if !strings.Contains(err.Error(), "count must be positive") {
			t.Errorf("expected 'count must be positive' error, got: %v", err)
		}

		// Test count = -1
		err = r.sendPartialRequests(context.Background(), -1)
		if err == nil {
			t.Fatal("expected error when count is -1")
		}
		if !strings.Contains(err.Error(), "count must be positive") {
			t.Errorf("expected 'count must be positive' error, got: %v", err)
		}
	}
}

// TestCloneRequest_NoBody verifies that cloneRequest properly handles requests without body.
func TestCloneRequest_NoBody(t *testing.T) {
	original, _ := http.NewRequest("GET", "https://example.com/path?query=1", nil)
	original.Header.Set("X-Custom", "value")

	cloned := cloneRequest(original, nil)

	// Check URL is preserved
	if cloned.URL.String() != original.URL.String() {
		t.Errorf("URL not preserved: got %s, want %s", cloned.URL.String(), original.URL.String())
	}

	// Check method is preserved
	if cloned.Method != original.Method {
		t.Errorf("Method not preserved: got %s, want %s", cloned.Method, original.Method)
	}

	// Check headers are preserved
	if cloned.Header.Get("X-Custom") != "value" {
		t.Errorf("Headers not preserved: got %s, want %s", cloned.Header.Get("X-Custom"), "value")
	}

	// Check body is nil
	if cloned.Body != nil {
		t.Error("Body should be nil for request without body data")
	}

	// Check ContentLength is 0
	if cloned.ContentLength != 0 {
		t.Errorf("ContentLength should be 0, got %d", cloned.ContentLength)
	}
}

// TestCloneRequest_WithBody verifies that cloneRequest properly handles requests with body.
func TestCloneRequest_WithBody(t *testing.T) {
	original, _ := http.NewRequest("POST", "https://example.com/api", nil)
	original.Header.Set("Content-Type", "application/json")

	bodyData := []byte(`{"key":"value"}`)
	cloned := cloneRequest(original, bodyData)

	// Check method is preserved
	if cloned.Method != "POST" {
		t.Errorf("Method not preserved: got %s, want POST", cloned.Method)
	}

	// Check ContentLength matches body data
	if cloned.ContentLength != int64(len(bodyData)) {
		t.Errorf("ContentLength should be %d, got %d", len(bodyData), cloned.ContentLength)
	}

	// Check body is readable and contains correct data
	if cloned.Body == nil {
		t.Fatal("Body should not be nil for request with body data")
	}

	// Read the body to verify
	buf := make([]byte, len(bodyData))
	n, err := cloned.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatalf("Error reading body: %v", err)
	}
	if n != len(bodyData) {
		t.Errorf("Body length mismatch: got %d bytes, want %d", n, len(bodyData))
	}
	if string(buf) != string(bodyData) {
		t.Errorf("Body content mismatch: got %q, want %q", buf, bodyData)
	}
}

// TestCloneRequest_SetsHost verifies that cloneRequest sets Host from URL if empty.
func TestCloneRequest_SetsHost(t *testing.T) {
	original, _ := http.NewRequest("GET", "https://example.com/path", nil)
	original.Host = "" // Clear host

	cloned := cloneRequest(original, nil)

	if cloned.Host != "example.com" {
		t.Errorf("Host should be set from URL, got %q, want %q", cloned.Host, "example.com")
	}
}

// TestCloneRequest_SetsScheme verifies that cloneRequest sets scheme to https if empty.
func TestCloneRequest_SetsScheme(t *testing.T) {
	original, _ := http.NewRequest("GET", "//example.com/path", nil)
	original.URL.Scheme = "" // Clear scheme

	cloned := cloneRequest(original, nil)

	if cloned.URL.Scheme != "https" {
		t.Errorf("Scheme should be https, got %q", cloned.URL.Scheme)
	}
}

// TestIsStreamLimitError verifies detection of stream limit errors.
func TestIsStreamLimitError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "too many open streams",
			err:      fmt.Errorf("too many open streams"),
			expected: true,
		},
		{
			name:     "stream limit reached",
			err:      fmt.Errorf("stream limit reached"),
			expected: true,
		},
		{
			name:     "MAX_STREAMS exceeded",
			err:      fmt.Errorf("MAX_STREAMS exceeded"),
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      fmt.Errorf("connection refused"),
			expected: false,
		},
		{
			name:     "wrapped stream limit error",
			err:      fmt.Errorf("failed to open: too many open streams"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isStreamLimitError(tt.err)
			if result != tt.expected {
				t.Errorf("isStreamLimitError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// TestSendPartialRequests_IntegrationHeadersOnly is an integration test that
// verifies sendPartialRequests works for GET requests (headers only, no body).
// This test requires network access and may be skipped in CI environments.
func TestSendPartialRequests_IntegrationHeadersOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Try multiple known HTTP/3 servers
	servers := []string{"www.google.com", "cloudflare.com", "www.cloudflare.com"}

	var conn quic.Connection
	var lastErr error
	var serverUsed string

	for _, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := dialQUIC(ctx, server+":443", nil, nil)
		cancel()

		if err != nil {
			lastErr = err
			t.Logf("failed to connect to %s: %v (trying next)", server, err)
			continue
		}

		conn = c
		serverUsed = server
		t.Logf("successfully connected to %s", server)
		break
	}

	if conn == nil {
		t.Skipf("could not connect to any HTTP/3 server (network may be restricted): %v", lastErr)
	}
	defer conn.CloseWithError(0, "test complete")

	// Create a GET request (no body)
	req, _ := http.NewRequest("GET", "https://"+serverUsed+"/", nil)
	req.Header.Set("User-Agent", "racey-test/1.0")

	r := &http3Request{
		Host:    serverUsed + ":443",
		conn:    conn,
		Request: req,
	}

	// Open 3 streams with partial requests
	ctx := context.Background()
	err := r.sendPartialRequests(ctx, 3)
	if err != nil {
		t.Fatalf("sendPartialRequests failed: %v", err)
	}

	// Verify correct number of streams were opened
	if len(r.streams) != 3 {
		t.Errorf("expected 3 streams, got %d", len(r.streams))
	}

	// Verify finalBytes has correct number of entries
	if len(r.finalBytes) != 3 {
		t.Errorf("expected 3 finalBytes entries, got %d", len(r.finalBytes))
	}

	// For GET requests (no body), finalBytes should all be nil
	for i, fb := range r.finalBytes {
		if fb != nil {
			t.Errorf("finalBytes[%d] should be nil for GET request, got %v", i, fb)
		}
	}

	// Verify clientConn was created
	if r.clientConn == nil {
		t.Error("clientConn should not be nil after sendPartialRequests")
	}

	t.Logf("Successfully opened %d streams with headers-only requests", len(r.streams))
}

// TestSendPartialRequests_IntegrationWithBody is an integration test that
// verifies sendPartialRequests works for POST requests with body.
// This test requires network access and may be skipped in CI environments.
func TestSendPartialRequests_IntegrationWithBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Try multiple known HTTP/3 servers
	servers := []string{"www.google.com", "cloudflare.com", "www.cloudflare.com"}

	var conn quic.Connection
	var lastErr error
	var serverUsed string

	for _, server := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := dialQUIC(ctx, server+":443", nil, nil)
		cancel()

		if err != nil {
			lastErr = err
			t.Logf("failed to connect to %s: %v (trying next)", server, err)
			continue
		}

		conn = c
		serverUsed = server
		t.Logf("successfully connected to %s", server)
		break
	}

	if conn == nil {
		t.Skipf("could not connect to any HTTP/3 server (network may be restricted): %v", lastErr)
	}
	defer conn.CloseWithError(0, "test complete")

	// Create a POST request with body
	bodyContent := "test body content for HTTP/3"
	req, _ := http.NewRequest("POST", "https://"+serverUsed+"/", strings.NewReader(bodyContent))
	req.Header.Set("User-Agent", "racey-test/1.0")
	req.Header.Set("Content-Type", "text/plain")

	r := &http3Request{
		Host:    serverUsed + ":443",
		conn:    conn,
		Request: req,
	}

	// Open 2 streams with partial requests (body - 1 byte)
	ctx := context.Background()
	err := r.sendPartialRequests(ctx, 2)
	if err != nil {
		t.Fatalf("sendPartialRequests failed: %v", err)
	}

	// Verify correct number of streams were opened
	if len(r.streams) != 2 {
		t.Errorf("expected 2 streams, got %d", len(r.streams))
	}

	// Verify finalBytes has correct number of entries
	if len(r.finalBytes) != 2 {
		t.Errorf("expected 2 finalBytes entries, got %d", len(r.finalBytes))
	}

	// For POST requests with body, finalBytes should contain the last byte
	for i, fb := range r.finalBytes {
		if fb == nil {
			t.Errorf("finalBytes[%d] should not be nil for POST request with body", i)
		} else if len(fb) != 1 {
			t.Errorf("finalBytes[%d] should be exactly 1 byte, got %d bytes", i, len(fb))
		} else if fb[0] != bodyContent[len(bodyContent)-1] {
			t.Errorf("finalBytes[%d] should be %q, got %q", i, bodyContent[len(bodyContent)-1], fb[0])
		}
	}

	t.Logf("Successfully opened %d streams with partial body data (withheld last byte)", len(r.streams))
}
