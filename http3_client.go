package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// http3Request holds the state for an HTTP/3 single packet attack.
// This mirrors the HTTP/2 request struct but uses QUIC/HTTP/3 types.
type http3Request struct {
	Host       string
	Request    *http.Request
	conn       quic.Connection
	clientConn *http3.ClientConn
	streams    []*http3.RequestStream
	responses  []*Response
}

// dialQUIC establishes a QUIC connection to the target host with TLS.
// It configures ALPN for HTTP/3 ("h3") and returns a connection ready
// for opening streams.
//
// The host parameter should be in "host:port" format. If no port is specified,
// port 443 is used by default.
//
// If tlsConfig is nil, a default configuration is created with:
//   - ALPN set to "h3" for HTTP/3
//   - InsecureSkipVerify set to true (matching HTTP/2 behavior)
//   - ServerName extracted from the host
//
// If quicConfig is nil, default QUIC settings are used.
func dialQUIC(ctx context.Context, host string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Connection, error) {
	// Ensure host has a port
	address := host
	if !strings.Contains(host, ":") {
		address = host + ":443"
	}

	// Extract hostname without port for SNI
	hostname := strings.Split(address, ":")[0]

	// Create default TLS config if not provided
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:         hostname,
			NextProtos:         []string{"h3"}, // ALPN for HTTP/3
			InsecureSkipVerify: true,           // Match HTTP/2 behavior
		}
	} else {
		// Ensure ALPN includes "h3" for HTTP/3
		hasH3 := false
		for _, proto := range tlsConfig.NextProtos {
			if proto == "h3" {
				hasH3 = true
				break
			}
		}
		if !hasH3 {
			tlsConfig.NextProtos = append([]string{"h3"}, tlsConfig.NextProtos...)
		}

		// Set ServerName if not already set
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = hostname
		}
	}

	// Dial the QUIC connection
	conn, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig)
	if err != nil {
		// Provide clear error messages for common failure scenarios
		if strings.Contains(err.Error(), "no recent network activity") {
			return nil, fmt.Errorf("HTTP/3 connection to %s timed out: %w", address, err)
		}
		if strings.Contains(err.Error(), "connection refused") {
			return nil, fmt.Errorf("HTTP/3 connection refused by %s (server may not support HTTP/3 on UDP/443): %w", address, err)
		}
		if strings.Contains(err.Error(), "network is unreachable") {
			return nil, fmt.Errorf("cannot reach %s (UDP may be blocked by firewall): %w", address, err)
		}
		if strings.Contains(err.Error(), "TLS") || strings.Contains(err.Error(), "tls") {
			return nil, fmt.Errorf("TLS handshake failed with %s: %w", address, err)
		}
		return nil, fmt.Errorf("failed to establish HTTP/3 connection to %s: %w", address, err)
	}

	return conn, nil
}

// sendPartialRequests implements Phase 1 of the Quic-Fin-Sync technique.
// It opens multiple QUIC streams, sends HEADERS frames for each request,
// but withholds the final byte/FIN flag to keep requests incomplete.
func (r *http3Request) sendPartialRequests(ctx context.Context, count int) error {
	// TODO: Implement partial request sending
	// - Use clientConn.OpenRequestStream() for each request
	// - Send request headers via SendRequestHeader()
	// - Write request body (if any) minus final byte
	// - Store streams for later FIN synchronization
	return fmt.Errorf("sendPartialRequests not yet implemented")
}

// sendFinalBytes implements Phase 2 of the Quic-Fin-Sync technique.
// It sends the final byte and FIN flag for all streams in rapid succession,
// triggering simultaneous server-side processing.
func (r *http3Request) sendFinalBytes() error {
	// TODO: Implement final byte synchronization
	// - Write final byte to each stream
	// - Call Close() on each stream to set FIN flag
	// - Ensure all close operations happen rapidly
	return fmt.Errorf("sendFinalBytes not yet implemented")
}

// readResponses collects HTTP/3 responses from all streams and
// converts them to the shared Response struct for analysis.
func (r *http3Request) readResponses() (map[uint32]*Response, error) {
	// TODO: Implement response collection
	// - Call ReadResponse() on each RequestStream
	// - Parse response headers and body
	// - Convert to Response struct (shared with HTTP/2)
	return nil, fmt.Errorf("readResponses not yet implemented")
}
