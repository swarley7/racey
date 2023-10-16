package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type request struct {
	Host        string
	Request     *http.Request
	framer      *http2.Framer
	streamID    uint32
	hbuf        bytes.Buffer
	henc        *hpack.Encoder
	peerSetting map[http2.SettingID]uint32
	hdec        *hpack.Decoder
}

/*
First, pre-send the bulk of each request:

If the request has no body, send all the headers, but don't set the END_STREAM flag. Withhold an empty data frame with END_STREAM set.
If the request has a body, send the headers and all the body data except the final byte. Withhold a data frame containing the final byte.
You might be tempted to send the full body and rely on not sending END_STREAM, but this will break on certain HTTP/2 server implementations that use the content-length header to decide when a message is complete, as opposed to waiting for END_STREAM.

Next, prepare to send the final frames:

Wait for 100ms to ensure the initial frames have been sent.
Ensure TCP_NODELAY is disabled - it's crucial that Nagle's algorithm batches the final frames.
Send a ping packet to warm the local connection. If you don't do this, the OS network stack will place the first final-frame in a separate packet.
*/

func client() {
	delay := time.Duration(100 * time.Millisecond)
	client := &http.Client{}
	client.Transport = &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
			cfg.InsecureSkipVerify = true
			tcpAddr, _ := net.ResolveTCPAddr("tcp4", addr)
			conn, err := net.DialTCP(netw, nil, tcpAddr)
			if err != nil {
				log.Println(err)
				return nil, err
			}
			conn.SetNoDelay(false) // Enable Nagle's algorithm to batch final frames
			return conn, err
		}}
	wg := sync.WaitGroup{}
	reqsChan := make(chan request)
	proceed := make(chan struct{}, 1)
	go gateRequests(wg, client, reqsChan, proceed)
	requests := []string{"https://www.google.com/"}
	for _, req := range requests {
		parsed, err := url.ParseRequestURI(req)
		if err != nil {
			panic(err)
		}
		address := parsed.Hostname()
		err = ping(address)
		if err != nil {
			log.Println(err)
		}
		r, err := http.NewRequest("GET", req, nil)
		if err != nil {
			panic(err)
		}
		resp, err := client.Do(r)
		if err != nil {
			panic(err)
		}
		log.Println(resp)
		reqsChan <- request{Host: req, Request: r}

	}
	doDelay(delay)
	// Ping the host
	err := ping("www.google.com") // Could change this to HTTP2 ping?
	if err != nil {
		panic(err)
	}
	wg.Add(1)
	proceed <- struct{}{}
	wg.Wait()
}

func gateRequests(wg sync.WaitGroup, client *http.Client, reqs chan request, proceed chan struct{}) {
	// Wait for everything to be ready
	gatedReqs := make(chan request)
	for req := range reqs {
		// Logic to do partial request here
		httpReq := req.Request
		if httpReq.ContentLength == 0 {

		} // Only headers here
		client.Do(httpReq)
	}
	select {
	case <-proceed:
		break
	}
	// wg.Add(1)
	go buildFinal(wg, gatedReqs)
	wg.Done()
}

func buildFinal(wg sync.WaitGroup, gatedReqs chan request) {

}

func doDelay(delay time.Duration) {
	time.Sleep(delay)
	return
}

func ping(address string) (err error) {
	err = nil
	pinger, err := probing.NewPinger(address)
	if err != nil {
		panic(err)
	}
	pinger.Count = 1
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
	return err
}

func main() {
	host := "www.example.com:443"
	app := &request{Host: host}
	app.henc = hpack.NewEncoder(&app.hbuf)

	cfg := &tls.Config{
		ServerName:         app.Host,
		NextProtos:         strings.Split("h2,h2-14", ","),
		InsecureSkipVerify: true,
	}
	hostAndPort := app.Host
	log.Printf("Connecting to %s ...", hostAndPort)
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", hostAndPort)

	conn, err := net.DialTCP("tcp4", nil, tcpAddr)
	if err != nil {
		panic(err)
	}
	conn.SetNoDelay(false)
	tc := tls.Client(conn, cfg)
	log.Printf("Connected to %v", tc.RemoteAddr())
	defer tc.Close()

	if err := tc.Handshake(); err != nil {
		log.Fatalf("TLS handshake: %v", err)
	}
	state := tc.ConnectionState()
	log.Printf("Negotiated protocol %q", state.NegotiatedProtocol)
	if !state.NegotiatedProtocolIsMutual || state.NegotiatedProtocol == "" {
		log.Fatalf("Could not negotiate protocol mutually")
	}
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		log.Fatalf("err %v", err)
	}
	app.framer = http2.NewFramer(tc, tc)

}

func (a *request) ReadRequest(args []string) (err error) {
	return err
}
