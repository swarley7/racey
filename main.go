package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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

func init() {

}

func main() {
	var Url, headers, requestFile, method string
	var count int
	var delay int64
	var debug bool
	flag.StringVar(&Url, "url", "https://localhost:8000", "Target URL")
	flag.StringVar(&method, "method", "GET", "HTTP Method")

	flag.StringVar(&headers, "headers", "", "HTTP headers to include (copy paste from Burp)")
	flag.StringVar(&requestFile, "request", "", "A file containing a HTTP request to load")
	flag.IntVar(&count, "count", 1, "Number of requests to send")
	flag.Int64Var(&delay, "delay", 1000, "Delay before sending final frames")
	flag.BoolVar(&debug, "debug", false, "Enable http2 debugging, log TLS keys for interception")

	flag.Parse()

	//Wrap this in a method and loop
	/* here*/
	var err error
	var req *http.Request
	if requestFile != "" {
		req, err = ReadRequest(requestFile)
	} else {
		req, err = http.NewRequest(method, Url, nil)
	}
	if err != nil {
		log.Fatalf("err %v", err)
	}
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443" //add port
	}
	app := &request{Host: host, peerSetting: make(map[http2.SettingID]uint32)}
	app.henc = hpack.NewEncoder(&app.hbuf)

	cfg := &tls.Config{
		ServerName:         app.Host,
		NextProtos:         strings.Split("h2,h2-14", ","),
		InsecureSkipVerify: true,
	}
	if debug {
		f, err := os.OpenFile("/tmp/keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		cfg.KeyLogWriter = f
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
	if state.NegotiatedProtocol == "" {
		log.Fatalf("Could not negotiate protocol mutually")
	}
	if _, err := io.WriteString(tc, http2.ClientPreface); err != nil {
		log.Fatalf("err %v", err)
	}
	app.framer = http2.NewFramer(tc, tc)
	// testing

	hbf := app.encodeHeaders(req)
	for i := 1; i <= count*2; i += 2 {
		app.streamID = uint32(i)
		// log.Println(hbf)
		log.Printf("Opening Stream-ID %d:\n", app.streamID)
		var settings []http2.Setting // TODO figure out if there's any benefit to modifying settings?
		app.framer.WriteSettings(settings...)
		app.framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      app.streamID,
			BlockFragment: hbf,
			EndStream:     false, // good enough for now
			EndHeaders:    true,  // for now
		})

	}
	log.Printf("Sent initial frames, waiting")

	doDelay(time.Duration(delay) * time.Millisecond)
	// var data [8]byte

	// copy(data[:], "lol_ping")
	log.Printf("Pinging host: %v", host)
	ping(strings.Split(host, ":")[0])
	for i := 1; i <= count*2; i += 2 {
		app.streamID = uint32(i)
		app.framer.WriteData(app.streamID, true, []byte{})
	}
	// time.Sleep(1000 * time.Millisecond)
	errc := make(chan error)
	go func() { errc <- app.readFrames() }()
	<-errc

	/* here */
}

func ReadRequest(filename string) (req *http.Request, err error) {
	log.Printf("Loading file: %v\n", filename)

	f, err := os.Open(filename)

	if err != nil {
		log.Printf("Error: %v\n", err)
		return nil, err
	}
	rawReq := bufio.NewReader(f)
	req, err = http.ReadRequest(rawReq)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return nil, err
	}
	return req, err
}

func (app *request) encodeHeaders(req *http.Request) []byte {
	app.hbuf.Reset()

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	app.writeHeader(":authority", host)
	app.writeHeader(":method", req.Method)
	app.writeHeader(":path", path)
	app.writeHeader(":scheme", "https")

	for k, vv := range req.Header {
		lowKey := strings.ToLower(k)
		if lowKey == "host" {
			continue
		}
		for _, v := range vv {
			app.writeHeader(lowKey, v)
		}
	}
	return app.hbuf.Bytes()
}

func (app *request) writeHeader(name, value string) {
	app.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

func (app *request) logf(format string, args ...interface{}) {
	log.Printf(format+"\r\n", args...)
}

func (app *request) readFrames() error {
	for {
		f, err := app.framer.ReadFrame()
		if err != nil {
			return fmt.Errorf("ReadFrame: %v", err)
		}
		app.logf("%v", f)
		switch f := f.(type) {
		case *http2.PingFrame:
			app.logf("  Data = %q", f.Data)
		case *http2.SettingsFrame:
			f.ForeachSetting(func(s http2.Setting) error {
				app.logf("  %v", s)
				app.peerSetting[s.ID] = s.Val
				return nil
			})
		case *http2.WindowUpdateFrame:
			app.logf("  Window-Increment = %v", f.Increment)
		case *http2.GoAwayFrame:
			app.logf("  Last-Stream-ID = %d; Error-Code = %v (%d)", f.LastStreamID, f.ErrCode, f.ErrCode)
		case *http2.DataFrame:
			app.logf("  %q", f.Data())
		case *http2.HeadersFrame:
			if f.HasPriority() {
				app.logf("  PRIORITY = %v", f.Priority)
			}
			if app.hdec == nil {
				// TODO: if the user uses h2i to send a SETTINGS frame advertising
				// something larger, we'll need to respect SETTINGS_HEADER_TABLE_SIZE
				// and stuff here instead of using the 4k default. But for now:
				tableSize := uint32(4 << 10)
				app.hdec = hpack.NewDecoder(tableSize, app.onNewHeaderField)
			}
			app.hdec.Write(f.HeaderBlockFragment())
		case *http2.PushPromiseFrame:
			if app.hdec == nil {
				// TODO: if the user uses h2i to send a SETTINGS frame advertising
				// something larger, we'll need to respect SETTINGS_HEADER_TABLE_SIZE
				// and stuff here instead of using the 4k default. But for now:
				tableSize := uint32(4 << 10)
				app.hdec = hpack.NewDecoder(tableSize, app.onNewHeaderField)
			}
			app.hdec.Write(f.HeaderBlockFragment())
		}
	}
}

func (app *request) onNewHeaderField(f hpack.HeaderField) {
	if f.Sensitive {
		app.logf("  %s = %q (SENSITIVE)", f.Name, f.Value)
	}
	app.logf("  %s = %q", f.Name, f.Value)
}
