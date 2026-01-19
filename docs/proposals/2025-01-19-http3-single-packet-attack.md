# Proposal: HTTP/3 Single Packet Attack Support

## Problem Statement

Racey is a race condition testing tool that exploits HTTP/2's stream multiplexing to send multiple requests in a single TCP packet, enabling detection of timing-sensitive vulnerabilities in web applications. The tool implements the "single packet attack" technique described by James Kettle at PortSwigger, which eliminates network jitter by ensuring all requests arrive at the server simultaneously within a single packet.

However, HTTP/3 adoption is growing rapidly, and many modern web applications now support or prefer HTTP/3 over HTTP/2. HTTP/3 uses QUIC (built on UDP) instead of TCP, which offers similar multiplexing capabilities but with different underlying mechanics. Security testers need the ability to perform race condition testing against HTTP/3 endpoints, which requires adapting the single packet attack technique to QUIC's architecture.

The goal of this enhancement is to extend Racey with HTTP/3/QUIC support, implementing a "Quic-Fin-Sync" technique (analogous to HTTP/2's last-byte synchronization) that withholds final bytes of each request stream, then releases them all in a single UDP packet to trigger simultaneous server-side processing.

## Research Findings

### Existing HTTP/2 Implementation

The current implementation in `main.go` uses a low-level approach to HTTP/2 frame manipulation:

**Connection Establishment (lines 252-288):**
- Creates a raw TCP connection with `net.DialTCP()` (line 268)
- Disables Nagle's algorithm with `conn.SetNoDelay(false)` (line 272) to allow packet batching
- Wraps in TLS with `h2` ALPN negotiation (lines 252-256)
- Writes HTTP/2 client preface manually (line 285)
- Creates an `http2.Framer` for low-level frame control (line 288)

**Request Structure (lines 23-35):**
```go
type request struct {
    Host        string
    Request     *http.Request
    framer      *http2.Framer
    streamID    uint32
    hbuf        bytes.Buffer
    henc        *hpack.Encoder
    peerSetting map[http2.SettingID]uint32
    hdec        *hpack.Decoder
    currentStreamID uint32
    streamHeaders   map[uint32]map[string]string
}
```

**Single Packet Attack Implementation (lines 291-317):**
1. **Phase 1 - Send Headers Without END_STREAM** (lines 291-305):
   - Iterates through `count` requests, assigning odd stream IDs (1, 3, 5...)
   - Calls `framer.WriteHeaders()` with `EndStream: false` (line 301)
   - All headers are sent but requests aren't complete

2. **Phase 2 - Delay** (line 308):
   - Waits for configurable delay (default 1000ms) via `-delay` flag
   - Ensures initial frames have been transmitted

3. **Phase 3 - Connection Warming** (lines 313):
   - Sends ICMP ping to warm the connection (`ping()` function, lines 89-101)
   - Prevents OS from placing first final frame in separate packet

4. **Phase 4 - Send Empty DATA Frames with END_STREAM** (lines 314-317):
   - Calls `framer.WriteData(streamID, true, []byte{})` for each stream
   - The `true` parameter sets END_STREAM flag
   - All frames sent in rapid succession, batched by TCP into single packet

**Header Encoding (lines 360-392):**
- Uses HPACK encoder to build HTTP/2 pseudo-headers (`:authority`, `:method`, `:path`, `:scheme`)
- Converts standard HTTP headers to lowercase as required by HTTP/2

**Response Collection (lines 402-506):**
- `readFrames()` collects responses from all streams
- Tracks `completedStreams` map to know when all requests have finished
- Handles HEADERS, DATA, RST_STREAM, and other frame types

**Response Analysis (lines 523-751):**
- `analyzeResponses()` compares all responses for variations
- Groups by status code, body content, body length
- Identifies varying headers across streams
- Outputs summary with race condition indicators

### HTTP/3/QUIC Technical Analysis

**QUIC Protocol Fundamentals:**
- QUIC is a UDP-based transport protocol (RFC 9000) that provides:
  - Multiplexed streams without head-of-line blocking
  - Built-in TLS 1.3 encryption
  - Connection migration support
  - 0-RTT connection establishment

**HTTP/3 over QUIC (RFC 9114):**
- Each HTTP request/response uses a separate QUIC stream
- HEADERS and DATA frames similar to HTTP/2 but encoded differently
- QPACK header compression (replaces HPACK)
- Stream FIN flag indicates request/response completion (analogous to END_STREAM)

**Single Packet Attack Translation (Quic-Fin-Sync):**

The technique translates well to QUIC with these adaptations:

1. **Phase 1 - Open Streams and Send Partial Data:**
   - Open multiple QUIC streams on a single connection
   - Send HEADERS frame for each stream
   - Send DATA frames but withhold the final byte of each request

2. **Phase 2 - Wait for Transmission:**
   - Brief delay to ensure partial frames reach the server

3. **Phase 3 - Send Final Bytes with FIN:**
   - Send the final byte of each stream with FIN flag set
   - All final bytes fit in a single UDP datagram (~1500 bytes MTU)
   - Server receives completion signals simultaneously

**Capacity Considerations:**
- UDP packets have ~1500 byte MTU (same practical limit as TCP)
- CyberArk's QuicDraw achieved 117 streams per sync packet
- For race condition testing, 20-30 requests is typically sufficient
- QUIC's MAX_STREAMS parameter (default 100-128) limits concurrent streams

**Available Go Libraries:**

**Primary Choice: `github.com/quic-go/quic-go`**
- Production-ready QUIC implementation in pure Go
- RFC 9000/9001/9002 compliant
- Includes `http3` subpackage for HTTP/3 support
- Provides low-level stream access via `OpenStream()`, `OpenStreamSync()`
- Key APIs for implementation:
  - `quic.DialAddr()` - Establish QUIC connection
  - `conn.OpenStream()` / `conn.OpenStreamSync()` - Create streams
  - `stream.Write()` - Send data
  - `stream.Close()` - Send FIN flag
  - `http3.Transport` - High-level HTTP/3 client
  - `http3.ClientConn.OpenRequestStream()` - Low-level request stream access

**Alternative: `golang.org/x/net/quic`**
- Official Go implementation (newer, less mature)
- Still in development/internal package
- Not recommended for production use yet

### Files to Modify/Create

**Files to Modify:**

- `main.go` - Add HTTP/3 flag parsing, protocol selection logic, and shared utilities
  - Add `-http3` / `--http3` boolean flag
  - Add `-alpn` flag for custom ALPN negotiation
  - Refactor response types to be protocol-agnostic
  - Extract common header parsing and response analysis

**Files to Create:**

- `http3_client.go` - HTTP/3/QUIC single packet attack implementation
  - `type http3Request struct` - QUIC stream state tracking
  - `func dialQUIC()` - Establish QUIC connection with TLS
  - `func (r *http3Request) encodeHeaders()` - QPACK header encoding
  - `func (r *http3Request) sendPartialRequests()` - Phase 1: Open streams, send headers + partial data
  - `func (r *http3Request) sendFinalBytes()` - Phase 2: Send final bytes with FIN
  - `func (r *http3Request) readResponses()` - Collect and parse HTTP/3 responses

- `go.mod` - Add quic-go dependency
  - `github.com/quic-go/quic-go v0.40+`

**Optional Future Files:**

- `http3_client_test.go` - Unit tests for HTTP/3 implementation
- `server_h3.go` - HTTP/3 test server for local development/testing

### Technical Constraints

**Dependencies:**
- `github.com/quic-go/quic-go` v0.40+ (production-ready QUIC implementation)
- Go 1.21+ recommended for quic-go compatibility
- TLS 1.3 required (QUIC mandate)

**Platform Considerations:**
- UDP socket access required (typically available)
- Some networks/firewalls may block UDP/443
- May require `CAP_NET_RAW` on Linux for some operations

**Protocol Limitations:**
- ~1500 byte UDP MTU limits payload per packet
- Server must support HTTP/3 (Alt-Svc header or prior knowledge)
- QUIC version negotiation may add latency on first connection
- MAX_STREAMS server setting may limit concurrent requests

**API Differences from HTTP/2:**
- No direct framer access in quic-go's http3 package
- May need to use lower-level QUIC stream API for fine-grained control
- QPACK encoding handled internally by http3 package

## Implementation Plan

### Approach

The implementation will follow a layered approach, first establishing basic HTTP/3 connectivity, then implementing the low-level stream manipulation required for the Quic-Fin-Sync technique.

The key insight is that while quic-go's `http3.Transport` provides high-level HTTP/3 support, the single packet attack requires low-level control over when stream FIN flags are sent. We'll use `http3.ClientConn.OpenRequestStream()` to get `RequestStream` objects that allow us to control exactly when headers are sent vs when the stream is closed. This mirrors the HTTP/2 approach where we use `framer.WriteHeaders()` with `EndStream: false` followed by `framer.WriteData()` with `EndStream: true`.

The existing code structure in `main.go` serves as a template: we'll create parallel types and functions for HTTP/3 that follow the same patterns (request struct with stream tracking, header encoding, phased transmission, response collection).

### Steps

1. **Add quic-go dependency and create http3_client.go scaffold**
   - Update `go.mod` with `github.com/quic-go/quic-go` dependency
   - Create `http3_client.go` with basic imports and type definitions
   - Define `http3Request` struct mirroring the HTTP/2 `request` struct
   - Rationale: Establishes the foundation for HTTP/3 code without modifying existing HTTP/2 functionality

2. **Implement QUIC connection establishment**
   - Create `dialQUIC()` function using `quic.DialAddr()` with TLS config
   - Configure ALPN for "h3" protocol
   - Handle connection errors and version negotiation
   - Rationale: QUIC connection is prerequisite for all HTTP/3 operations

3. **Implement stream opening and partial request sending**
   - Use `http3.Transport.NewClientConn()` to get `ClientConn`
   - Call `OpenRequestStream()` to create request streams
   - Use `SendRequestHeader()` to send HEADERS frames
   - Write request body (if any) minus final byte using `Write()`
   - Rationale: This is Phase 1 of Quic-Fin-Sync - getting requests to the "almost complete" state

4. **Implement final byte synchronization**
   - After delay, write final byte to each stream
   - Call `Close()` on each stream to set FIN flag
   - Ensure all close operations happen in rapid succession
   - Rationale: This is Phase 2 - triggering simultaneous request completion on the server

5. **Implement HTTP/3 response collection**
   - Call `ReadResponse()` on each RequestStream
   - Parse response headers and body
   - Convert to shared `Response` struct for analysis
   - Rationale: Response collection allows reuse of existing analysis code

6. **Add CLI flag and protocol selection in main.go**
   - Add `-http3` boolean flag to flag parsing
   - Add conditional logic to choose HTTP/2 vs HTTP/3 code path
   - Refactor any duplicated utilities (header parsing, response analysis)
   - Rationale: Provides user interface for the new functionality

7. **Test and refine timing parameters**
   - Test against HTTP/3 servers (e.g., Cloudflare, Google)
   - Tune delay between phases for optimal synchronization
   - Verify responses show expected timing behavior
   - Rationale: Ensures the technique works in practice, not just theory

### Testing Strategy

**Unit Tests (http3_client_test.go):**
- Test QUIC connection establishment with mock server
- Test header encoding produces valid QPACK output
- Test stream management (open, write, close)
- Test response parsing for various HTTP/3 response formats

**Integration Tests:**
- Create `server_h3.go` - local HTTP/3 test server
  - Endpoint that logs request arrival times with microsecond precision
  - Endpoint that returns different responses based on request order
  - Endpoint that simulates race-vulnerable behavior
- Test that multiple requests arrive within expected time window
- Test that response analysis correctly identifies variations

**Manual Testing:**
- Test against public HTTP/3 servers (cloudflare.com, google.com)
- Test against local HTTP/3 server with artificial race conditions
- Verify `-http3` flag works correctly
- Test error handling (non-HTTP/3 server, connection failures)

**Comparison Testing:**
- Run same tests against HTTP/2 and HTTP/3 endpoints
- Compare timing precision between protocols
- Verify response analysis produces consistent results

## Risks and Mitigations

- **Risk:** quic-go's http3 package may not expose sufficient low-level control for Quic-Fin-Sync
  - **Mitigation:** Fall back to using raw QUIC streams (`conn.OpenStream()`) and manually implementing HTTP/3 framing. The `RequestStream` API with `SendRequestHeader()` and separate `Write()`/`Close()` should provide the needed control, but if not, raw streams give complete control at the cost of more implementation work.

- **Risk:** Server MAX_STREAMS limits may prevent opening enough concurrent streams
  - **Mitigation:** Respect server's advertised MAX_STREAMS setting. Most servers allow 100+ concurrent streams which is sufficient for race condition testing. Add warning if user requests more streams than allowed.

- **Risk:** UDP packet size limits may constrain attack effectiveness
  - **Mitigation:** The ~1500 byte MTU is actually similar to TCP's practical limit. With minimal final-byte payloads (1 byte per stream + QUIC framing), we can fit 100+ stream completions in a single packet. Document this limitation and provide guidance on optimal request count.

- **Risk:** HTTP/3 server adoption may be inconsistent, leading to connection failures
  - **Mitigation:** Implement clear error messages when HTTP/3 connection fails. Consider adding automatic fallback to HTTP/2 with user notification. Add `-alpn` flag for manual protocol override.

- **Risk:** QUIC's built-in congestion control and pacing may interfere with single-packet timing
  - **Mitigation:** The final bytes are small enough that they shouldn't trigger pacing. If issues arise, investigate quic-go's config options for disabling pacing on small writes. The approach used by QuicDraw shows this is achievable in practice.

- **Risk:** Different QUIC implementations (server-side) may behave differently
  - **Mitigation:** Test against multiple HTTP/3 server implementations (nginx, Cloudflare, Google). Document any server-specific behaviors discovered during testing.

## Acceptance Criteria

- [ ] New `-http3` CLI flag enables HTTP/3 mode
- [ ] Tool successfully establishes QUIC connections to HTTP/3 servers
- [ ] Multiple HTTP/3 requests are sent with stream FINs synchronized in single packet
- [ ] Response analysis works identically for HTTP/3 responses (status codes, headers, body comparison)
- [ ] Existing HTTP/2 functionality remains unchanged when `-http3` is not specified
- [ ] Error messages are clear when HTTP/3 connection fails (e.g., server doesn't support HTTP/3)
- [ ] Tool handles server MAX_STREAMS limits gracefully
- [ ] `-count` flag works with HTTP/3 (respecting protocol limits)
- [ ] `-delay` flag works with HTTP/3 for timing control
- [ ] `-log` flag captures HTTP/3 response details
- [ ] Documentation updated with HTTP/3 usage examples in README.md

## References

- [PortSwigger: Smashing the state machine (single packet attack)](https://portswigger.net/research/smashing-the-state-machine)
- [PortSwigger: The single-packet attack](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local)
- [CyberArk: Racing and Fuzzing HTTP/3 (QuicDraw)](https://www.cyberark.com/resources/threat-research-blog/racing-and-fuzzing-http-3-open-sourcing-quicdraw)
- [quic-go GitHub Repository](https://github.com/quic-go/quic-go)
- [quic-go Documentation](https://quic-go.net/)
- [quic-go http3 Package API](https://pkg.go.dev/github.com/quic-go/quic-go/http3)
- [RFC 9000: QUIC Transport Protocol](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
