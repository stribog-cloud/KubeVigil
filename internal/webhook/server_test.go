package webhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stribog-cloud/kubevigil/internal/checker"
)

func TestNewServer_RequiresTLS(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	if _, err := NewServer(&Config{}, h); err == nil {
		t.Fatal("server without TLS material must error")
	}
}

func TestNewServer_BadCertPath(t *testing.T) {
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	if _, err := NewServer(&Config{CertFile: "/nope/cert.pem", KeyFile: "/nope/key.pem"}, h); err == nil {
		t.Fatal("server with unreadable cert must error")
	}
}

// genSelfSigned writes a self-signed cert/key pair for the given host and
// returns their paths.
func genSelfSigned(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = certOut.Close()
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = keyOut.Close()
	return certPath, keyPath
}

func TestServer_EndToEndTLS(t *testing.T) {
	cert, key := genSelfSigned(t)
	h := &Handler{
		Scanner: &fakeScanner{findings: []checker.Finding{
			{Checker: "privileged", Severity: checker.SeverityCritical, Resource: "web", Message: "priv"},
		}},
		FailOn: checker.SeverityHigh,
	}
	srv, err := NewServer(&Config{Addr: "127.0.0.1:0", CertFile: cert, KeyFile: key}, h)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.http.ServeTLS(ln, cert, key) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.http.Shutdown(ctx)
	}()

	body, _ := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
		"request": map[string]any{"uid": "e2e", "object": map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": "web", "namespace": "default"},
		}},
	})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}} //nolint:gosec // test client against a self-signed local cert
	resp, err := client.Post("https://"+ln.Addr().String()+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	respObj, _ := out["response"].(map[string]any)
	if allowed, _ := respObj["allowed"].(bool); allowed {
		t.Error("critical finding should have been denied over the wire")
	}

	// Health endpoint returns 200.
	hresp, err := client.Get("https://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d", hresp.StatusCode)
	}
}

func TestServer_RunStartsAndShutsDownOnContextCancel(t *testing.T) {
	cert, key := genSelfSigned(t)
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	srv, err := NewServer(&Config{Addr: "127.0.0.1:0", CertFile: cert, KeyFile: key}, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	// Give the listener a moment to come up, then cancel to trigger shutdown.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestServer_RunReturnsListenError(t *testing.T) {
	cert, key := genSelfSigned(t)
	h := &Handler{Scanner: &fakeScanner{}, FailOn: checker.SeverityHigh}
	// An invalid address makes ListenAndServeTLS fail immediately.
	srv, err := NewServer(&Config{Addr: "256.256.256.256:99999", CertFile: cert, KeyFile: key}, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Run(context.Background()); err == nil {
		t.Error("Run should return the listen error")
	}
}
