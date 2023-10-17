# racey
Race condition tester using HTTP/2


# dev server

Gen a server cert and key with:

`openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt`

then run `go run server.go` to spawn a HTTP2 server on `localhost:8000`
