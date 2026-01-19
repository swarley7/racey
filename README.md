# racey
Race condition tester using HTTP/2

Abuses the single packet attack described in https://portswigger.net/research/smashing-the-state-machine (thanks albinowax!) to time multiple HTTP/2 requests at the same time. Can be abused to realise subtle state differences in application's handling of such requests, or to identify instances whereby time-based properties are exposed (tokens seeded on time, etc.).


# Example Servers

See [`examples/README.md`](examples/README.md) for vulnerable test servers demonstrating race conditions.

Quick start:
```bash
# HTTP/2 server (port 8000)
go run examples/example_vulnerable_http2.go

# HTTP/3 server (port 8443)
go run examples/example_vulnerable_http3.go
```

Test with racey:
```bash
./racey -url "https://localhost:8000/redeem?code=DISCOUNT50" -count 10       # HTTP/2
./racey -http3 -url "https://localhost:8443/redeem?code=DISCOUNT50" -count 10 # HTTP/3
```
