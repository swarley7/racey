# racey

Race condition testing tool for HTTP/2 and HTTP/3 using single packet attacks.

## Overview

Racey exploits the single packet attack technique described in [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine) (PortSwigger Research) to send multiple HTTP requests simultaneously. By synchronizing the final bytes of multiple requests into a single TCP packet (HTTP/2) or UDP packet (HTTP/3), requests arrive at the server at virtually the same moment, exposing race condition vulnerabilities.

**Use cases:**
- Detect TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
- Identify state machine inconsistencies
- Find time-seeded token predictability
- Test concurrent request handling

## Installation

```bash
go build -o racey .
```

## Quick Start

```bash
# HTTP/2 (default)
./racey -url "https://target.com/api/redeem?code=VOUCHER" -count 10

# HTTP/3
./racey -http3 -url "https://target.com/api/redeem?code=VOUCHER" -count 10
```

## Usage

```
Usage: racey [options]

Options:
  -url string       Target URL (default "https://localhost:8000")
  -method string    HTTP method (default "GET")
  -headers string   HTTP headers to include (Burp Suite format)
  -request string   File containing an HTTP request template
  -count int        Number of requests to send (default 1)
  -delay int        Delay before sending final frames in ms (default 1000)
  -http3            Use HTTP/3 (QUIC) instead of HTTP/2
  -debug            Enable HTTP/2 debugging, log TLS keys for interception
  -prettify         Prettify the output of HTTP/2 responses (default true)
  -log string       Log file path for full untruncated response analysis
```

## How It Works

### HTTP/2 Single Packet Attack

1. **Open streams**: Send HEADERS frames for N requests without END_STREAM flag
2. **Wait**: Allow server to begin processing partial requests
3. **Warm connection**: Send ICMP ping to ensure TCP buffers are ready
4. **Synchronize**: Send all final DATA frames with END_STREAM in a single TCP packet

### HTTP/3 Quic-Fin-Sync

1. **Open streams**: Send HEADERS and partial body on QUIC streams
2. **Wait**: Allow server to begin processing
3. **Synchronize**: Send final bytes and FIN flags in tight loop (~20µs for 5 streams)

## Examples

### Basic GET request race

```bash
./racey -url "https://api.example.com/voucher/redeem?code=SAVE50" -count 10
```

### POST request with body

```bash
./racey -url "https://api.example.com/transfer" \
  -method POST \
  -headers "Content-Type: application/json" \
  -count 5
```

### Load request from file (Burp format)

```bash
./racey -request request.txt -count 10
```

### HTTP/3 with custom delay

```bash
./racey -http3 -url "https://h3.example.com/api" -count 10 -delay 500
```

### Debug mode with logging

```bash
./racey -url "https://target.com/api" -count 10 -debug -log responses.txt
```

## Detecting Vulnerabilities

Racey compares responses to identify variations that indicate race conditions:

| Variation | Possible Vulnerability |
|-----------|------------------------|
| Different status codes (200 vs 400) | Authorization bypass, double-spend |
| Different response bodies | State inconsistency |
| Different headers (Set-Cookie) | Session handling race |
| Same success for single-use resource | TOCTOU vulnerability |

## Example Vulnerable Servers

Test servers are included in the `examples/` directory to demonstrate race condition vulnerabilities.

```bash
# Generate certs (servers auto-generate if not present)
cd examples

# HTTP/2 server (port 8000)
go run example_vulnerable_http2.go

# HTTP/3 server (port 8443)
go run example_vulnerable_http3.go
```

Test the race condition:

```bash
# HTTP/2
./racey -url "https://localhost:8000/redeem?code=DISCOUNT50" -count 10

# HTTP/3
./racey -http3 -url "https://localhost:8443/redeem?code=DISCOUNT50" -count 10
```

**Expected result:** Multiple "SUCCESS" responses for a single-use voucher indicates the race condition was exploited.

See [`examples/README.md`](examples/README.md) for detailed documentation.

## Protocol Support

| Protocol | Transport | Flag | Port (examples) |
|----------|-----------|------|-----------------|
| HTTP/2 | TCP + TLS | (default) | 8000 |
| HTTP/3 | QUIC (UDP) + TLS 1.3 | `-http3` | 8443 |

## Credits

- Single packet attack technique: [PortSwigger Research](https://portswigger.net/research/smashing-the-state-machine) by James Kettle (albinowax)
- HTTP/3 Quic-Fin-Sync: Inspired by CyberArk's QuicDraw research

## License

See [LICENSE](LICENSE) file.
