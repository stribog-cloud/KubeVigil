package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/stribog-cloud/kubevigil/internal/checker"
	"github.com/stribog-cloud/kubevigil/internal/engine"
	"github.com/stribog-cloud/kubevigil/internal/webhook"
)

var (
	flagWebhookAddr    string
	flagWebhookCert    string
	flagWebhookKey     string
	flagWebhookPath    string
	flagWebhookFailOn  string
	flagWebhookTimeout time.Duration
)

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Run as a Kubernetes validating admission webhook",
	Long: "Serve a ValidatingAdmissionWebhook that scans each admitted object with " +
		"KubeVigil's checks and custom policies, denying admission for findings at or " +
		"above --fail-on severity and surfacing the rest as admission warnings.\n\n" +
		"Requires a TLS serving certificate (the Kubernetes API server only calls " +
		"webhooks over HTTPS). See docs/integrations/admission-webhook.md and " +
		"deploy/webhook/ for the ValidatingWebhookConfiguration and manifests.",
	RunE: runWebhook,
}

func init() {
	webhookCmd.Flags().StringVar(&flagWebhookAddr, "addr", ":8443", "listen address")
	webhookCmd.Flags().StringVar(&flagWebhookCert, "tls-cert", "", "path to the PEM TLS serving certificate (required)")
	webhookCmd.Flags().StringVar(&flagWebhookKey, "tls-key", "", "path to the PEM TLS private key (required)")
	webhookCmd.Flags().StringVar(&flagWebhookPath, "path", "/validate", "URL path for admission requests")
	webhookCmd.Flags().StringVar(&flagWebhookFailOn, "fail-on", "high", "minimum severity that denies admission (info, low, medium, high, critical)")
	webhookCmd.Flags().DurationVar(&flagWebhookTimeout, "scan-timeout", 5*time.Second, "per-object scan timeout")
	rootCmd.AddCommand(webhookCmd)
}

func runWebhook(cmd *cobra.Command, _ []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		return &exitError{code: 3, err: err}
	}

	failOn, err := checker.ParseSeverity(flagWebhookFailOn)
	if err != nil {
		return &exitError{code: 3, err: fmt.Errorf("invalid --fail-on %q: %w (valid: info, low, medium, high, critical)", flagWebhookFailOn, err)}
	}

	// Build a per-process registry seeded from the built-ins plus custom
	// policies, exactly as scan does — the webhook enforces the same checks.
	registry := checker.NewRegistry()
	for _, c := range checker.DefaultRegistry().All() {
		registry.MustRegister(c)
	}
	if regErr := registerCustomPolicies(registry, cfg); regErr != nil {
		fmt.Fprintf(os.Stderr, "Policy error: %v\n", regErr)
		return &exitError{code: 3, err: regErr}
	}

	scanner := engine.NewScanner(registry, cfg)
	handler := &webhook.Handler{
		Scanner:     scanner,
		FailOn:      failOn,
		ScanTimeout: flagWebhookTimeout,
	}

	srv, err := webhook.NewServer(&webhook.Config{
		Addr:     flagWebhookAddr,
		CertFile: flagWebhookCert,
		KeyFile:  flagWebhookKey,
		Path:     flagWebhookPath,
	}, handler)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Webhook error: %v\n", err)
		return &exitError{code: 3, err: err}
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("webhook server: %w", err)
	}
	return nil
}
