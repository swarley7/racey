package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
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
	streams    []http3.RequestStream
	responses  []*Response
	// finalBytes holds the last byte of the request body for each stream,
	// to be sent during the synchronized final byte phase.
	// For requests without a body, this will be nil (empty DATA frame with FIN).
	finalBytes [][]byte
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
//
// For requests with a body:
//   - Sends HEADERS frame
//   - Writes all body data except the final byte
//   - Stores the final byte for later synchronization
//
// For requests without a body:
//   - Sends HEADERS frame only
//   - Stores nil for final bytes (empty DATA frame with FIN will be sent)
//
// The function requires that r.conn is already established via dialQUIC.
// It creates an http3.ClientConn and stores it in r.clientConn.
func (r *http3Request) sendPartialRequests(ctx context.Context, count int) error {
	if r.conn == nil {
		return fmt.Errorf("QUIC connection not established: call dialQUIC first")
	}
	if r.Request == nil {
		return fmt.Errorf("request not set: set r.Request before calling sendPartialRequests")
	}
	if count <= 0 {
		return fmt.Errorf("count must be positive, got %d", count)
	}

	// Create HTTP/3 transport and client connection
	transport := &http3.Transport{}
	r.clientConn = transport.NewClientConn(r.conn)

	// Initialize slices for tracking streams and final bytes
	r.streams = make([]http3.RequestStream, 0, count)
	r.finalBytes = make([][]byte, 0, count)

	// Read the request body once if present, so we can split it for each stream
	var bodyData []byte
	if r.Request.Body != nil {
		var err error
		bodyData, err = io.ReadAll(r.Request.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// Close the original body
		r.Request.Body.Close()
	}

	// Track how many streams we've successfully opened
	successfullyOpened := 0

	for i := 0; i < count; i++ {
		// Open a new request stream
		stream, err := r.clientConn.OpenRequestStream(ctx)
		if err != nil {
			// Check if we hit the server's stream limit
			if isStreamLimitError(err) {
				log.Printf("WARNING: Server MAX_STREAMS limit reached after opening %d streams (requested %d)", successfullyOpened, count)
				if successfullyOpened == 0 {
					return fmt.Errorf("server MAX_STREAMS limit prevents opening any streams: %w", err)
				}
				// Continue with the streams we have
				break
			}
			return fmt.Errorf("failed to open request stream %d: %w", i, err)
		}

		// Clone the request for this stream
		clonedReq := cloneRequest(r.Request, bodyData)

		// Send request headers
		// Note: SendRequestHeader is for requests without a body.
		// For requests with a body, we need to use Write() which implicitly sends headers.
		if len(bodyData) == 0 {
			// No body: send headers only via SendRequestHeader
			if err := stream.SendRequestHeader(clonedReq); err != nil {
				return fmt.Errorf("failed to send headers on stream %d: %w", i, err)
			}
			// Store nil for final bytes - we'll send empty DATA with FIN
			r.finalBytes = append(r.finalBytes, nil)
		} else {
			// Has body: we need to send headers + partial body
			// The http3 package's RequestStream.Write() will send headers on first write.
			// But we want to send headers first, then body data minus final byte.

			// First, send the headers using SendRequestHeader
			// Note: According to the docs, SendRequestHeader can only be used for
			// requests without a body AND cannot be called after Write().
			// For requests WITH a body, we need a different approach.

			// Actually, looking at the http3 API more carefully:
			// - SendRequestHeader: for requests without body
			// - Write: sends headers (if not sent) + body data
			// - Close: sends FIN

			// For our use case with body, we need to:
			// 1. Write headers + all body data except last byte
			// 2. NOT call Close (that would send FIN)
			// 3. Later call Write(lastByte) + Close()

			// The http3 RequestStream doesn't have a separate SendRequestHeader
			// for requests with bodies. Instead, we write directly.

			// Write all but the final byte
			partialBody := bodyData[:len(bodyData)-1]
			finalByte := bodyData[len(bodyData)-1:]

			// Write partial body (this sends headers + body data, but no FIN)
			if _, err := stream.Write(partialBody); err != nil {
				return fmt.Errorf("failed to write partial body on stream %d: %w", i, err)
			}

			// Store the final byte for later synchronization
			r.finalBytes = append(r.finalBytes, finalByte)
		}

		r.streams = append(r.streams, stream)
		successfullyOpened++
	}

	log.Printf("Opened %d HTTP/3 streams with partial requests", successfullyOpened)
	return nil
}

// isStreamLimitError checks if the error indicates the server's stream limit was reached.
func isStreamLimitError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// quic-go returns "too many open streams" when limit is reached
	return strings.Contains(errStr, "too many open streams") ||
		strings.Contains(errStr, "stream limit") ||
		strings.Contains(errStr, "MAX_STREAMS")
}

// cloneRequest creates a clone of the http.Request suitable for sending on a new stream.
// If bodyData is provided, it creates a new body reader from it.
func cloneRequest(req *http.Request, bodyData []byte) *http.Request {
	// Clone the request
	cloned := req.Clone(req.Context())

	// Set up the body if we have data
	if len(bodyData) > 0 {
		cloned.Body = io.NopCloser(bytes.NewReader(bodyData))
		cloned.ContentLength = int64(len(bodyData))
	} else {
		cloned.Body = nil
		cloned.ContentLength = 0
	}

	// Ensure required HTTP/3 pseudo-headers are properly set
	// :authority comes from Host
	if cloned.Host == "" && cloned.URL != nil {
		cloned.Host = cloned.URL.Host
	}

	// :scheme should be https for HTTP/3
	if cloned.URL != nil && cloned.URL.Scheme == "" {
		cloned.URL.Scheme = "https"
	}

	return cloned
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
