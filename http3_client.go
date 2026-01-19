package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

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
func dialQUIC(ctx context.Context, host string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Connection, error) {
	// TODO: Implement QUIC connection establishment
	// - Use quic.DialAddr() with the provided configs
	// - Configure ALPN for "h3" protocol
	// - Handle version negotiation
	return nil, fmt.Errorf("dialQUIC not yet implemented")
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
