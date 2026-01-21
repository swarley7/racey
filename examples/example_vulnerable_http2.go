// example_vulnerable_http2.go demonstrates a race-prone voucher redemption server.
//
// This server intentionally implements a TOCTOU (Time-Of-Check to Time-Of-Use)
// vulnerability in the voucher redemption endpoint. The vulnerability allows
// multiple simultaneous requests to redeem the same voucher by exploiting the
// race window between checking if a voucher exists and deleting it.
//
// VULNERABILITY EXPLAINED:
// 1. Request A checks if voucher exists (check passes)
// 2. Request B checks if voucher exists (check passes)
// 3. Request A sleeps for 10ms (race window)
// 4. Request B sleeps for 10ms (race window)
// 5. Request A deletes voucher and returns SUCCESS
// 6. Request B deletes voucher (already deleted, but no error) and returns SUCCESS
//
// Both requests successfully "redeem" the voucher, demonstrating the race condition.
//
// Usage:
//
//	go run examples/example_vulnerable_http2.go
//
// Then test with racey:
//
//	go run . -url "https://localhost:8000/redeem?code=DISCOUNT50" -count 10
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

// vouchers is a shared map storing valid voucher codes.
// VULNERABLE: This map is accessed without synchronization, making it
// susceptible to race conditions when multiple goroutines access it concurrently.
var vouchers = map[string]bool{
	"DISCOUNT50": true,
	"FREEBIE":    true,
	"SAVE20":     true,
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/redeem", handleRedeem)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/reset", handleReset)

	// Generate self-signed certificate for TLS/HTTP2
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	srv := &http.Server{
		Addr:    ":8000",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}

	log.Printf("Starting vulnerable HTTP/2 server on https://localhost:8000")
	log.Printf("Available endpoints:")
	log.Printf("  GET /         - Server info")
	log.Printf("  GET /redeem?code=<CODE> - Redeem a voucher (VULNERABLE)")
	log.Printf("  GET /status   - List available vouchers")
	log.Printf("  POST /reset   - Reset vouchers to initial state")
	log.Printf("")
	log.Printf("Valid voucher codes: DISCOUNT50, FREEBIE, SAVE20")
	log.Printf("")
	log.Printf("Test with racey:")
	log.Printf("  go run . -url \"https://localhost:8000/redeem?code=DISCOUNT50\" -count 10")

	// ListenAndServeTLS with empty strings uses TLSConfig.Certificates
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.Proto, r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Vulnerable Voucher Server (HTTP/2)\n")
	fmt.Fprintf(w, "Protocol: %s\n", r.Proto)
	fmt.Fprintf(w, "\nEndpoints:\n")
	fmt.Fprintf(w, "  GET /redeem?code=<CODE> - Redeem a voucher\n")
	fmt.Fprintf(w, "  GET /status - List available vouchers\n")
	fmt.Fprintf(w, "  POST /reset - Reset vouchers\n")
}

// handleRedeem implements the VULNERABLE voucher redemption logic.
//
// TOCTOU VULNERABILITY:
// The check (vouchers[code]) and the use (delete) are separated by a sleep,
// creating a race window. Multiple concurrent requests can all pass the check
// before any of them execute the delete.
func handleRedeem(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	log.Printf("[%s] %s %s?code=%s", r.Proto, r.Method, r.URL.Path, code)

	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "FAILED: Missing 'code' parameter")
		return
	}

	// VULNERABLE: Check-then-act without synchronization
	// This is the Time-Of-Check (TOC) - multiple goroutines can pass this check
	// before any of them reach the delete operation.
	if vouchers[code] {
		// RACE WINDOW: This sleep simulates processing time and widens
		// the race window. In real applications, this could be database
		// operations, external API calls, or any non-trivial processing.
		time.Sleep(10 * time.Millisecond)

		// VULNERABLE: This is the Time-Of-Use (TOU) - by the time we get here,
		// other requests may have already passed the check above.
		// The delete operation doesn't return an error if the key doesn't exist,
		// so we can't detect that another request already redeemed it.
		delete(vouchers, code)

		log.Printf("[SUCCESS] Voucher %s redeemed", code)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "SUCCESS: Voucher redeemed!")
	} else {
		log.Printf("[FAILED] Voucher %s invalid or already used", code)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "FAILED: Invalid or already used")
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.Proto, r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Available vouchers:\n")
	for code := range vouchers {
		fmt.Fprintf(w, "  - %s\n", code)
	}
	if len(vouchers) == 0 {
		fmt.Fprintf(w, "  (none)\n")
	}
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	log.Printf("[%s] %s %s", r.Proto, r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "FAILED: Use POST method")
		return
	}

	vouchers = map[string]bool{
		"DISCOUNT50": true,
		"FREEBIE":    true,
		"SAVE20":     true,
	}
	log.Printf("[RESET] Vouchers restored")
	fmt.Fprintf(w, "SUCCESS: Vouchers reset")
}

// generateSelfSignedCert creates a self-signed TLS certificate for the server.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Racey Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}

	_ = privDER // privDER is generated but we use priv directly

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf: &x509.Certificate{
			Raw: certDER,
		},
	}, nil
}
