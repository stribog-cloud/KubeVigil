package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Config configures the webhook HTTPS server.
type Config struct {
	// Addr is the listen address, e.g. ":8443".
	Addr string
	// CertFile / KeyFile are the PEM serving cert and key. Required — the
	// Kubernetes API server only calls webhooks over TLS.
	CertFile string
	KeyFile  string
	// Path is the URL path the ValidatingWebhookConfiguration points at.
	Path string
	// HealthPath serves an unauthenticated liveness/readiness 200.
	HealthPath string
}

// Server wraps an http.Server serving the admission Handler over TLS.
type Server struct {
	cfg     Config
	handler *Handler
	http    *http.Server
}

// NewServer builds a webhook server. It validates that TLS material is
// configured (a webhook without TLS is unusable — the API server refuses it).
func NewServer(cfgPtr *Config, handler *Handler) (*Server, error) {
	cfg := *cfgPtr // local copy; defaults below must not mutate the caller's struct
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("webhook requires --tls-cert and --tls-key (the Kubernetes API server only calls webhooks over HTTPS)")
	}
	if cfg.Path == "" {
		cfg.Path = "/validate"
	}
	if cfg.HealthPath == "" {
		cfg.HealthPath = "/healthz"
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	// Fail fast if the cert/key don't load, rather than at first request.
	if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
		return nil, fmt.Errorf("loading TLS keypair: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, handler)
	mux.HandleFunc(cfg.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &Server{
		cfg:     cfg,
		handler: handler,
		http: &http.Server{
			Addr:              cfg.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// Run starts the TLS server and blocks until ctx is cancelled, then gracefully
// shuts down.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("admission webhook listening",
			"addr", s.cfg.Addr, "path", s.cfg.Path, "fail_on", s.handler.FailOn.String())
		err := s.http.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
