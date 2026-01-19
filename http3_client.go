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
	"sync"
	"time"

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
//
// For each stream:
//   - Writes the final byte (if any body was present)
//   - Calls Close() to send the FIN flag
//
// All operations happen in a tight loop for maximum synchronization.
// The goal is to have all FIN frames batched in a single UDP packet.
//
// Errors on individual streams are collected but don't stop processing
// of other streams. This ensures maximum synchronization even if some
// streams encounter issues.
//
// Returns an error only if ALL streams fail. If some streams succeed
// and some fail, returns nil but logs the failures.
func (r *http3Request) sendFinalBytes() error {
	if len(r.streams) == 0 {
		return fmt.Errorf("no streams to send final bytes on: call sendPartialRequests first")
	}

	// Track which streams failed (a single stream can have multiple errors)
	failedStreams := make(map[int]bool)
	// Track all errors for logging
	type streamError struct {
		index int
		err   error
	}
	var errors []streamError

	// Tight loop to send all final bytes and FINs in rapid succession
	// This is the critical synchronization point - all close operations
	// should happen as close together as possible to fit in one UDP packet
	for i, stream := range r.streams {
		// Write the final byte if this stream has one
		if r.finalBytes[i] != nil && len(r.finalBytes[i]) > 0 {
			if _, err := stream.Write(r.finalBytes[i]); err != nil {
				failedStreams[i] = true
				errors = append(errors, streamError{index: i, err: fmt.Errorf("failed to write final byte: %w", err)})
				// Continue to try closing even if write fails
			}
		}

		// Close the stream to send FIN flag
		// This is the key synchronization - all FINs should go out together
		if err := stream.Close(); err != nil {
			failedStreams[i] = true
			errors = append(errors, streamError{index: i, err: fmt.Errorf("failed to close stream: %w", err)})
		}
	}

	// Report results
	if len(failedStreams) > 0 {
		// Log individual stream errors
		for _, se := range errors {
			log.Printf("Stream %d error during final byte sync: %v", se.index, se.err)
		}

		// Only return error if ALL streams failed
		if len(failedStreams) == len(r.streams) {
			return fmt.Errorf("all %d streams failed during final byte synchronization", len(r.streams))
		}

		// Some succeeded, some failed - log warning but don't error
		log.Printf("WARNING: %d/%d streams encountered errors during final byte sync", len(failedStreams), len(r.streams))
	} else {
		log.Printf("Sent final bytes and FIN flags on all %d streams", len(r.streams))
	}

	return nil
}

// readResponses collects HTTP/3 responses from all streams and
// converts them to the shared Response struct for analysis.
//
// For each stream:
//   - Calls ReadResponse() to get the HTTP response (headers)
//   - Reads the response body fully
//   - Converts to the shared Response struct used by analyzeResponses()
//
// The function uses concurrent goroutines to read responses in parallel,
// with a configurable timeout (default 30 seconds) for slow responses.
//
// Error handling:
//   - Individual stream errors are captured in Response.Error
//   - The function continues processing other streams even if some fail
//   - Only returns an error if ALL streams fail
//
// Returns a map of StreamID (as uint32) to Response for compatibility
// with the existing analyzeResponses() function.
func (r *http3Request) readResponses() (map[uint32]*Response, error) {
	return r.readResponsesWithTimeout(30 * time.Second)
}

// readResponsesWithTimeout is the internal implementation that accepts a custom timeout.
// This is useful for testing with shorter timeouts.
func (r *http3Request) readResponsesWithTimeout(timeout time.Duration) (map[uint32]*Response, error) {
	if len(r.streams) == 0 {
		return nil, fmt.Errorf("no streams to read responses from: call sendPartialRequests first")
	}

	// Create response map with mutex for concurrent access
	responses := make(map[uint32]*Response)
	var mu sync.Mutex

	// Use WaitGroup to wait for all goroutines
	var wg sync.WaitGroup

	// Track how many streams succeed vs fail
	var successCount, failCount int32

	// Read responses concurrently from all streams
	for i, stream := range r.streams {
		wg.Add(1)
		go func(idx int, s http3.RequestStream) {
			defer wg.Done()

			// Get stream ID for tracking
			streamID := uint32(s.StreamID())

			// Create context with timeout for this response read
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Channel to receive the response result
			type readResult struct {
				resp *http.Response
				err  error
			}
			resultCh := make(chan readResult, 1)

			// Read response in a goroutine so we can apply timeout
			go func() {
				resp, err := s.ReadResponse()
				resultCh <- readResult{resp, err}
			}()

			// Wait for response or timeout
			select {
			case result := <-resultCh:
				if result.err != nil {
					// Stream failed to read response
					mu.Lock()
					responses[streamID] = &Response{
						StreamID: streamID,
						Error:    fmt.Sprintf("failed to read response: %v", result.err),
					}
					failCount++
					mu.Unlock()
					log.Printf("Stream %d: failed to read response: %v", streamID, result.err)
					return
				}

				// Successfully got response headers, now read the body
				response := convertHTTPResponse(streamID, result.resp, s, timeout-time.Since(time.Now()))
				mu.Lock()
				responses[streamID] = response
				if response.Error != "" {
					failCount++
				} else {
					successCount++
				}
				mu.Unlock()

			case <-ctx.Done():
				// Timeout reading response
				mu.Lock()
				responses[streamID] = &Response{
					StreamID: streamID,
					Error:    fmt.Sprintf("timeout reading response after %v", timeout),
				}
				failCount++
				mu.Unlock()
				log.Printf("Stream %d: timeout reading response", streamID)

				// Cancel the stream to clean up
				s.CancelRead(0x100) // H3_REQUEST_CANCELLED
			}
		}(i, stream)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Log summary
	log.Printf("Read %d responses: %d successful, %d failed", len(responses), successCount, failCount)

	// Only return error if ALL streams failed
	if failCount == int32(len(r.streams)) && failCount > 0 {
		return responses, fmt.Errorf("all %d streams failed to read responses", len(r.streams))
	}

	return responses, nil
}

// runHTTP3Attack orchestrates the full HTTP/3 single packet attack.
// It implements the Quic-Fin-Sync technique:
//  1. Establish QUIC connection
//  2. Send partial requests (headers + body minus final byte)
//  3. Wait for specified delay
//  4. Send final bytes and FIN flags in rapid succession
//  5. Read and return responses
//
// Parameters:
//   - req: The HTTP request template to use for all streams
//   - count: Number of concurrent requests to send
//   - delay: Delay in milliseconds between partial requests and final byte sync
//
// Returns the collected responses and any error encountered.
func runHTTP3Attack(req *http.Request, count int, delay int64) (map[uint32]*Response, error) {
	ctx := context.Background()

	// Extract host for QUIC connection
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host == "" {
		return nil, fmt.Errorf("cannot determine host from request")
	}

	log.Printf("Establishing HTTP/3 connection to %s...", host)

	// Phase 0: Establish QUIC connection
	conn, err := dialQUIC(ctx, host, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 connection failed: %w\nNote: Ensure the server supports HTTP/3 on UDP port 443", err)
	}
	defer conn.CloseWithError(0, "done")

	log.Printf("Connected via QUIC to %v", conn.RemoteAddr())

	// Create HTTP/3 request object
	h3req := &http3Request{
		Host:    host,
		Request: req,
		conn:    conn,
	}

	// Phase 1: Send partial requests (headers + body minus final byte)
	log.Printf("Phase 1: Sending %d partial requests...", count)
	if err := h3req.sendPartialRequests(ctx, count); err != nil {
		return nil, fmt.Errorf("failed to send partial requests: %w", err)
	}

	// Phase 2: Wait for delay to ensure partial frames are transmitted
	log.Printf("Phase 2: Waiting %d ms before final byte sync...", delay)
	time.Sleep(time.Duration(delay) * time.Millisecond)

	// Phase 3: Send final bytes and FIN flags (Quic-Fin-Sync)
	log.Printf("Phase 3: Sending final bytes and FIN flags...")
	if err := h3req.sendFinalBytes(); err != nil {
		return nil, fmt.Errorf("failed to send final bytes: %w", err)
	}

	// Phase 4: Read responses
	log.Printf("Phase 4: Reading responses...")
	responses, err := h3req.readResponses()
	if err != nil {
		return responses, fmt.Errorf("error reading responses: %w", err)
	}

	return responses, nil
}

// convertHTTPResponse converts an *http.Response to our shared Response struct.
// It reads the full body and extracts headers into a map.
func convertHTTPResponse(streamID uint32, httpResp *http.Response, stream http3.RequestStream, remainingTimeout time.Duration) *Response {
	resp := &Response{
		StreamID: streamID,
		Status:   fmt.Sprintf("%d", httpResp.StatusCode),
		Headers:  make(map[string]string),
	}

	// Copy headers, converting to single string values
	// HTTP/3 headers are already lowercase per spec
	for name, values := range httpResp.Header {
		// Join multiple values with comma (standard HTTP header format)
		resp.Headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}

	// Add the :status pseudo-header for compatibility with HTTP/2 response analysis
	resp.Headers[":status"] = resp.Status

	// Read the response body fully
	// The body is read from the stream after ReadResponse() has parsed headers
	if httpResp.Body != nil {
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			resp.Error = fmt.Sprintf("failed to read response body: %v", err)
			log.Printf("Stream %d: failed to read body: %v", streamID, err)
		} else {
			resp.Body = body
		}
	}

	return resp
}
