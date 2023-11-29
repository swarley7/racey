# racey
Race condition tester using HTTP/2

Abuses the single packet attack described in https://portswigger.net/research/smashing-the-state-machine (thanks albinowax!) to time multiple HTTP/2 requests at the same time. Can be abused to realise subtle state differences in application's handling of such requests, or to identify instances whereby time-based properties are exposed (tokens seeded on time, etc.).


# dev server

Gen a server cert and key with:

`openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt`

then run `go run server.go` to spawn a HTTP2 server on `localhost:8000`
