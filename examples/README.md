# Example Vulnerable Servers

These example servers demonstrate race condition vulnerabilities that can be detected and exploited using the `racey` tool. Both servers implement intentionally vulnerable voucher redemption endpoints with a TOCTOU (Time-Of-Check to Time-Of-Use) vulnerability.

## The Vulnerability

The servers contain a classic TOCTOU race condition:

1. **Check**: Request checks if voucher exists in the map
2. **Race Window**: 10ms sleep simulates processing (database query, API call, etc.)
3. **Use**: Voucher is deleted from the map

Multiple simultaneous requests can all pass the check before any of them execute the delete, allowing the same voucher to be "redeemed" multiple times.

## Quick Start

The example servers generate self-signed TLS certificates automatically at startup - no manual certificate generation required.

### HTTP/2 Server (Port 8000)

```bash
# Terminal 1: Start the server
go run examples/example_vulnerable_http2.go

# Terminal 2: Test with racey
./racey -url "https://localhost:8000/redeem?code=DISCOUNT50" -count 10
```

### HTTP/3 Server (Port 8443)

```bash
# Terminal 1: Start the server
go run examples/example_vulnerable_http3.go

# Terminal 2: Test with racey
./racey -http3 -url "https://localhost:8443/redeem?code=DISCOUNT50" -count 10
```

## Server Endpoints

Both servers expose the same endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info and protocol version |
| `/redeem?code=<CODE>` | GET | Redeem a voucher (VULNERABLE) |
| `/status` | GET | List available vouchers |
| `/reset` | POST | Reset vouchers to initial state |

## Valid Voucher Codes

- `DISCOUNT50`
- `FREEBIE`
- `SAVE20`

## Expected Output

When the race condition is successfully exploited, you'll see multiple `SUCCESS` responses for a single-use voucher:

```
$ ./racey -url "https://localhost:8000/redeem?code=DISCOUNT50" -count 10

[Response 1] Status: 200
SUCCESS: Voucher redeemed!

[Response 2] Status: 200
SUCCESS: Voucher redeemed!

[Response 3] Status: 200
SUCCESS: Voucher redeemed!

[Response 4] Status: 400
FAILED: Invalid or already used

...
```

Multiple `SUCCESS` responses indicate the race condition was triggered - the voucher was redeemed more than once.

## Server Logs

The server logs show the race condition clearly:

```
2024/01/15 10:30:00 [HTTP/2.0] GET /redeem?code=DISCOUNT50
2024/01/15 10:30:00 [HTTP/2.0] GET /redeem?code=DISCOUNT50
2024/01/15 10:30:00 [HTTP/2.0] GET /redeem?code=DISCOUNT50
2024/01/15 10:30:00 [SUCCESS] Voucher DISCOUNT50 redeemed
2024/01/15 10:30:00 [SUCCESS] Voucher DISCOUNT50 redeemed
2024/01/15 10:30:00 [SUCCESS] Voucher DISCOUNT50 redeemed
2024/01/15 10:30:00 [FAILED] Voucher DISCOUNT50 invalid or already used
```

## Resetting Vouchers

After testing, reset the vouchers to their initial state:

```bash
curl -X POST https://localhost:8000/reset -k   # HTTP/2
curl -X POST https://localhost:8443/reset -k   # HTTP/3
```

## Protocol Differences

### HTTP/2 (TCP)
- Uses TCP with TLS 1.2+
- Stream multiplexing over a single TCP connection
- Requests are sent using HTTP/2's single-packet attack technique

### HTTP/3 (QUIC/UDP)
- Uses QUIC over UDP with built-in TLS 1.3
- Independent streams without head-of-line blocking
- Can achieve even tighter request timing due to QUIC's design
- Use the `-http3` flag with racey

## Building racey

```bash
go build -o racey .
```

## Additional racey Options

```
-count int     Number of requests to send (default 1)
-delay int     Delay before sending final frames in ms (default 1000)
-method string HTTP method (default "GET")
-headers string HTTP headers to include
-request string File containing an HTTP request template
-debug         Enable debug logging
-log string    Log file for full response analysis
```
