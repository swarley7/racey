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
	// Track current stream's headers being decoded
	currentStreamID uint32
	streamHeaders   map[uint32]map[string]string
}

// Response holds a collected HTTP/2 response
type Response struct {
	StreamID uint32
	Status   string
	Headers  map[string]string
	Body     []byte
	Error    string
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

// parseBurpHeaders parses headers copied from Burp Suite
// Format: "Header-Name: value" separated by newlines
// Handles both \n and \r\n line endings
func parseBurpHeaders(headerStr string) http.Header {
	headers := make(http.Header)
	if headerStr == "" {
		return headers
	}

	// Normalize line endings and split
	headerStr = strings.ReplaceAll(headerStr, "\r\n", "\n")
	lines := strings.Split(headerStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split on first colon only (header values can contain colons)
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			log.Printf("Warning: skipping malformed header line: %q", line)
			continue
		}

		name := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		if name == "" {
			continue
		}

		headers.Add(name, value)
	}

	return headers
}

// applyHeaders merges parsed headers into an existing request
// Overwrites existing headers with the same name
func applyHeaders(req *http.Request, headers http.Header) {
	for name, values := range headers {
		// Delete existing header first to overwrite
		req.Header.Del(name)
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
}

func main() {
	var Url, headers, requestFile, method, logFile string
	var count int
	var delay int64
	var debug, prettify bool
	flag.StringVar(&Url, "url", "https://localhost:8000", "Target URL")
	flag.StringVar(&method, "method", "GET", "HTTP Method")

	flag.StringVar(&headers, "headers", "", "HTTP headers to include (copy paste from Burp)")
	flag.StringVar(&requestFile, "request", "", "A file containing a HTTP request to load")
	flag.IntVar(&count, "count", 1, "Number of requests to send")
	flag.Int64Var(&delay, "delay", 1000, "Delay before sending final frames")
	flag.BoolVar(&debug, "debug", false, "Enable http2 debugging, log TLS keys for interception")
	flag.BoolVar(&prettify, "prettify", true, "Prettify the output of HTTP2 responses")
	flag.StringVar(&logFile, "log", "", "Log file path for full untruncated response analysis")

	flag.Parse()

	// Setup log file if specified
	var logWriter *os.File
	if logFile != "" {
		var err error
		logWriter, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logWriter.Close()
		fmt.Fprintf(logWriter, "\n%s\n", strings.Repeat("=", 80))
		fmt.Fprintf(logWriter, "RACEY LOG - %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(logWriter, "%s\n", strings.Repeat("=", 80))
		fmt.Fprintf(logWriter, "\nINPUT PARAMETERS:\n")
		fmt.Fprintf(logWriter, "  URL: %s\n", Url)
		fmt.Fprintf(logWriter, "  Method: %s\n", method)
		fmt.Fprintf(logWriter, "  Count: %d\n", count)
		fmt.Fprintf(logWriter, "  Delay: %d ms\n", delay)
		if requestFile != "" {
			fmt.Fprintf(logWriter, "  Request File: %s\n", requestFile)
			// Include the raw request file contents
			if reqFileContents, err := os.ReadFile(requestFile); err == nil {
				fmt.Fprintf(logWriter, "\nRAW REQUEST FILE CONTENTS:\n")
				fmt.Fprintf(logWriter, "%s\n", strings.Repeat("-", 40))
				fmt.Fprintf(logWriter, "%s\n", string(reqFileContents))
				fmt.Fprintf(logWriter, "%s\n", strings.Repeat("-", 40))
			}
		}
		if headers != "" {
			fmt.Fprintf(logWriter, "  Custom Headers:\n")
			for _, line := range strings.Split(headers, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					fmt.Fprintf(logWriter, "    %s\n", line)
				}
			}
		}
		fmt.Fprintf(logWriter, "\nCOMMAND LINE (for repeatability):\n")
		fmt.Fprintf(logWriter, "  go run main.go -url %q -method %s -count %d -delay %d",
			Url, method, count, delay)
		if requestFile != "" {
			fmt.Fprintf(logWriter, " -request %q", requestFile)
		}
		if headers != "" {
			fmt.Fprintf(logWriter, " -headers %q", headers)
		}
		if debug {
			fmt.Fprintf(logWriter, " -debug")
		}
		fmt.Fprintf(logWriter, "\n")
	}

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

	// Apply custom headers from -headers flag (Burp format)
	if headers != "" {
		customHeaders := parseBurpHeaders(headers)
		applyHeaders(req, customHeaders)
		if debug {
			log.Printf("Applied %d custom header(s)", len(customHeaders))
		}
	}

	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443" //add port
	}
	app := &request{Host: host, peerSetting: make(map[http2.SettingID]uint32)}
	app.henc = hpack.NewEncoder(&app.hbuf)

	cfg := &tls.Config{
		ServerName:         strings.Split(app.Host, ":")[0], // SNI must not include port
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
	type result struct {
		responses map[uint32]*Response
		err       error
	}
	resultc := make(chan result, 1)
	go func() {
		responses, err := app.readFrames(count)
		resultc <- result{responses, err}
	}()
	res := <-resultc
	if res.err != nil {
		log.Printf("Finished with error: %v", res.err)
	} else {
		log.Printf("Completed successfully")
		analyzeResponses(res.responses, logWriter)
	}
}

func (app *request) compileResponse() (string, error) {

	return "", nil
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
	// Include query string in :path if present
	if req.URL.RawQuery != "" {
		path = path + "?" + req.URL.RawQuery
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

func (app *request) readFrames(expectedStreams int) (map[uint32]*Response, error) {
	responses := make(map[uint32]*Response)
	bodyBuffers := make(map[uint32]*bytes.Buffer)
	completedStreams := make(map[uint32]bool)

	// Initialize streamHeaders map
	app.streamHeaders = make(map[uint32]map[string]string)

	for {
		f, err := app.framer.ReadFrame()
		if err != nil {
			if err == io.EOF {
				app.logf("Connection closed by server")
				return responses, nil
			}
			return responses, fmt.Errorf("ReadFrame: %v", err)
		}
		app.logf("%v", f)

		// Check for stream completion via END_STREAM flag
		streamEnded := false
		var streamID uint32

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
			return responses, nil
		case *http2.DataFrame:
			app.logf("  %q", f.Data())
			streamID = f.StreamID
			// Accumulate body data
			if bodyBuffers[streamID] == nil {
				bodyBuffers[streamID] = &bytes.Buffer{}
			}
			bodyBuffers[streamID].Write(f.Data())
			streamEnded = f.StreamEnded()
		case *http2.HeadersFrame:
			streamID = f.StreamID
			if f.HasPriority() {
				app.logf("  PRIORITY = %v", f.Priority)
			}
			if app.hdec == nil {
				tableSize := uint32(4 << 10)
				app.hdec = hpack.NewDecoder(tableSize, app.onNewHeaderField)
			}
			// Initialize headers map for this stream
			if app.streamHeaders[streamID] == nil {
				app.streamHeaders[streamID] = make(map[string]string)
			}
			app.currentStreamID = streamID
			app.hdec.Write(f.HeaderBlockFragment())
			streamEnded = f.StreamEnded()
		case *http2.RSTStreamFrame:
			app.logf("  %q - [%d]", f.ErrCode.String(), f.StreamID)
			streamID = f.StreamID
			// Create error response
			if responses[streamID] == nil {
				responses[streamID] = &Response{StreamID: streamID}
			}
			responses[streamID].Error = f.ErrCode.String()
			completedStreams[streamID] = true
		case *http2.PushPromiseFrame:
			if app.hdec == nil {
				tableSize := uint32(4 << 10)
				app.hdec = hpack.NewDecoder(tableSize, app.onNewHeaderField)
			}
			app.hdec.Write(f.HeaderBlockFragment())
		}

		// Mark stream as completed if END_STREAM was set
		if streamEnded && streamID > 0 {
			completedStreams[streamID] = true
			app.logf("Stream %d completed (END_STREAM)", streamID)

			// Build the response object
			resp := &Response{
				StreamID: streamID,
				Headers:  app.streamHeaders[streamID],
			}
			if resp.Headers != nil {
				resp.Status = resp.Headers[":status"]
			}
			if bodyBuffers[streamID] != nil {
				resp.Body = bodyBuffers[streamID].Bytes()
			}
			responses[streamID] = resp
		}

		// Check if all expected streams are done
		if len(completedStreams) >= expectedStreams {
			app.logf("All %d streams completed", expectedStreams)
			return responses, nil
		}
	}
}

func (app *request) onNewHeaderField(f hpack.HeaderField) {
	if f.Sensitive {
		app.logf("  %s = %q (SENSITIVE)", f.Name, f.Value)
	}
	app.logf("  %s = %q", f.Name, f.Value)

	// Store header in the current stream's headers map
	if app.streamHeaders != nil && app.currentStreamID > 0 {
		if app.streamHeaders[app.currentStreamID] == nil {
			app.streamHeaders[app.currentStreamID] = make(map[string]string)
		}
		app.streamHeaders[app.currentStreamID][f.Name] = f.Value
	}
}

// analyzeResponses compares all responses and reports variations
// If logWriter is provided, writes full untruncated output to it
func analyzeResponses(responses map[uint32]*Response, logWriter *os.File) {
	// Helper to write to both stdout and log file
	output := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		if logWriter != nil {
			fmt.Fprintf(logWriter, format, args...)
		}
	}

	// Helper to write only to log file (for full untruncated data)
	logOnly := func(format string, args ...interface{}) {
		if logWriter != nil {
			fmt.Fprintf(logWriter, format, args...)
		}
	}

	if len(responses) == 0 {
		output("\n" + strings.Repeat("=", 60) + "\n")
		output("NO RESPONSES RECEIVED\n")
		output(strings.Repeat("=", 60) + "\n")
		return
	}

	output("\n" + strings.Repeat("=", 60) + "\n")
	output("RESPONSE ANALYSIS\n")
	output(strings.Repeat("=", 60) + "\n")

	// Group responses by status code
	statusGroups := make(map[string][]uint32)
	// Group responses by body content
	bodyGroups := make(map[string][]uint32)
	// Group responses by body length
	lengthGroups := make(map[int][]uint32)
	// Track all header names and their values across streams
	headerValues := make(map[string]map[string][]uint32) // header -> value -> streams

	for streamID, resp := range responses {
		if resp.Error != "" {
			statusGroups["ERROR:"+resp.Error] = append(statusGroups["ERROR:"+resp.Error], streamID)
			continue
		}

		status := resp.Status
		if status == "" {
			status = "UNKNOWN"
		}
		statusGroups[status] = append(statusGroups[status], streamID)

		bodyStr := string(resp.Body)
		bodyGroups[bodyStr] = append(bodyGroups[bodyStr], streamID)

		lengthGroups[len(resp.Body)] = append(lengthGroups[len(resp.Body)], streamID)

		// Collect header values
		for headerName, headerValue := range resp.Headers {
			if headerValues[headerName] == nil {
				headerValues[headerName] = make(map[string][]uint32)
			}
			headerValues[headerName][headerValue] = append(headerValues[headerName][headerValue], streamID)
		}
	}

	// Report status code distribution
	output("\n📊 Status Code Distribution:\n")
	for status, streams := range statusGroups {
		output("   [%s] × %d (streams: %v)\n", status, len(streams), streams)
	}

	// Report body length distribution
	output("\n📏 Response Length Distribution:\n")
	for length, streams := range lengthGroups {
		output("   [%d bytes] × %d (streams: %v)\n", length, len(streams), streams)
	}

	// Find headers that vary
	varyingHeaders := make(map[string]map[string][]uint32)
	for headerName, values := range headerValues {
		if len(values) > 1 {
			varyingHeaders[headerName] = values
		}
	}

	// Report header variations
	totalResponses := len(responses)
	if len(varyingHeaders) > 0 {
		output("\n🔀 Varying Headers:\n")
		for headerName, values := range varyingHeaders {
			// Count total streams that have this header
			streamsWithHeader := 0
			for _, streams := range values {
				streamsWithHeader += len(streams)
			}
			uniqueValues := len(values)
			output("   %s (%d unique in %d/%d responses):\n", headerName, uniqueValues, streamsWithHeader, totalResponses)
			for value, streams := range values {
				// Truncated for stdout
				displayValue := value
				if len(displayValue) > 60 {
					displayValue = displayValue[:60] + "..."
				}
				fmt.Printf("      [%s] × %d (streams: %v)\n", displayValue, len(streams), streams)
				// Full value for log file
				if logWriter != nil {
					fmt.Fprintf(logWriter, "      [%s] × %d (streams: %v)\n", value, len(streams), streams)
				}
			}
		}
	} else {
		output("\n🔒 Headers: All identical across responses\n")
	}

	// Determine if responses vary
	output("\n" + strings.Repeat("-", 60) + "\n")

	statusVaries := len(statusGroups) > 1
	bodyVaries := len(bodyGroups) > 1
	headersVary := len(varyingHeaders) > 0

	if !statusVaries && !bodyVaries && !headersVary {
		output("✅ ALL RESPONSES IDENTICAL\n")
		output("   Status: %s | Body Length: %d bytes\n",
			responses[getFirstKey(responses)].Status,
			len(responses[getFirstKey(responses)].Body))
	} else {
		output("⚠️  RESPONSES VARY!\n")

		if statusVaries {
			output("   ↳ Status codes differ\n")
		}
		if headersVary {
			output("   ↳ %d header(s) differ: %s\n", len(varyingHeaders), getHeaderNames(varyingHeaders))
		}
		if bodyVaries {
			output("   ↳ Response bodies differ\n")
			output("   ↳ %d unique response(s) detected\n", len(bodyGroups))
		}

		// Show unique responses
		output("\n📝 Unique Responses:\n")
		shown := make(map[string]bool)
		i := 1
		for streamID, resp := range responses {
			bodyKey := string(resp.Body)
			if shown[bodyKey] {
				continue
			}
			shown[bodyKey] = true

			output("\n   Response #%d (Stream %d):\n", i, streamID)
			output("   Status: %s\n", resp.Status)

			// Show varying headers for this response
			if headersVary {
				output("   Varying Headers:\n")
				for headerName := range varyingHeaders {
					if val, ok := resp.Headers[headerName]; ok {
						// Truncated for stdout
						displayVal := val
						if len(displayVal) > 50 {
							displayVal = displayVal[:50] + "..."
						}
						fmt.Printf("      %s: %s\n", headerName, displayVal)
						// Full value for log file
						if logWriter != nil {
							fmt.Fprintf(logWriter, "      %s: %s\n", headerName, val)
						}
					}
				}
			}

			output("   Body Length: %d bytes\n", len(resp.Body))

			// Show truncated body preview for stdout
			bodyPreview := string(resp.Body)
			if len(bodyPreview) > 200 {
				fmt.Printf("   Body Preview:\n   %s...\n", strings.ReplaceAll(bodyPreview[:200], "\n", "\n   "))
			} else if bodyPreview != "" {
				fmt.Printf("   Body Preview:\n   %s\n", strings.ReplaceAll(bodyPreview, "\n", "\n   "))
			}

			// Full body for log file
			if logWriter != nil {
				fmt.Fprintf(logWriter, "   Full Body:\n   %s\n", strings.ReplaceAll(string(resp.Body), "\n", "\n   "))
			}

			i++
		}
	}

	output("\n" + strings.Repeat("=", 60) + "\n")

	// Write full response details to log file
	if logWriter != nil {
		logOnly("\n" + strings.Repeat("=", 80) + "\n")
		logOnly("FULL RESPONSE DETAILS\n")
		logOnly(strings.Repeat("=", 80) + "\n")

		for streamID, resp := range responses {
			logOnly("\n--- Stream %d ---\n", streamID)
			logOnly("Status: %s\n", resp.Status)
			if resp.Error != "" {
				logOnly("Error: %s\n", resp.Error)
			}
			logOnly("\nHeaders:\n")
			for name, value := range resp.Headers {
				logOnly("   %s: %s\n", name, value)
			}
			logOnly("\nBody (%d bytes):\n%s\n", len(resp.Body), string(resp.Body))
			logOnly(strings.Repeat("-", 40) + "\n")
		}
	}
}

func getFirstKey(m map[uint32]*Response) uint32 {
	for k := range m {
		return k
	}
	return 0
}

func getHeaderNames(headers map[string]map[string][]uint32) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
