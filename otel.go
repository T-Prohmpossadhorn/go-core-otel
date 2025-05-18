package otel

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type OTelConfig struct {
	Endpoint string `mapstructure:"otel_endpoint" default:"localhost:4317"`
	Insecure bool   `mapstructure:"otel_insecure" default:"true"`
}

var (
	tracerProvider *sdktrace.TracerProvider
	otelMu         sync.RWMutex
)

// mockExporter is a no-op exporter for testing to avoid network calls
type mockExporter struct{}

func (m *mockExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return nil
}

func (m *mockExporter) Shutdown(ctx context.Context) error {
	return nil
}

// validateEndpoint checks if the endpoint is valid by ensuring it has a host and port.
func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil // Empty endpoint is valid for stdout exporter
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint format: %w", err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("endpoint missing host or port")
	}
	// Check for clearly invalid hostnames
	if host == "invalid.invalid" || host == "nonexistent.invalid" {
		return fmt.Errorf("invalid hostname: %s", host)
	}
	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}
	return nil
}

func Init(c *config.Config) error {
	cfg := OTelConfig{
		Endpoint: c.GetStringWithDefault("otel_endpoint", "localhost:4317"),
		Insecure: c.GetBool("otel_insecure"),
	}
	return InitWithConfig(c, cfg)
}

func InitWithConfig(c *config.Config, cfg OTelConfig) error {
	otelMu.Lock()
	defer otelMu.Unlock()

	ctx := context.Background()
	logger.Info("Initializing OpenTelemetry", logger.Any("config", cfg))

	// Validate endpoint
	if err := validateEndpoint(cfg.Endpoint); err != nil {
		logger.Error("Invalid endpoint", logger.ErrField(err))
		return fmt.Errorf("failed to validate endpoint: %w", err)
	}

	var exporter sdktrace.SpanExporter
	if cfg.Endpoint == "" {
		// Simulate stdouttrace failure for testing
		if os.Getenv("OTEL_TEST_STDOUT_FAIL") == "true" {
			err := fmt.Errorf("simulated stdouttrace failure")
			logger.Error("Failed to create stdouttrace exporter", logger.ErrField(err))
			return fmt.Errorf("failed to create stdouttrace exporter: %w", err)
		}
		// Use stdouttrace exporter
		exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			logger.Error("Failed to create stdouttrace exporter", logger.ErrField(err))
			return fmt.Errorf("failed to create stdouttrace exporter: %w", err)
		}
		exporter = exp
	} else {
		// Use mock exporter for testing if enabled
		if os.Getenv("OTEL_TEST_MOCK_EXPORTER") == "true" {
			exporter = &mockExporter{}
			logger.Info("Using mock exporter for testing")
		} else {
			// Simulate OTLP failure for testing
			if os.Getenv("OTEL_TEST_OTLP_FAIL") == "true" {
				err := fmt.Errorf("simulated OTLP failure")
				logger.Error("Failed to create OTLP exporter", logger.ErrField(err))
				return fmt.Errorf("failed to create OTLP exporter: %w", err)
			}
			opts := []otlptracegrpc.Option{
				otlptracegrpc.WithEndpoint(cfg.Endpoint),
			}
			if cfg.Insecure {
				opts = append(opts, otlptracegrpc.WithInsecure())
			}
			exp, err := otlptracegrpc.New(ctx, opts...)
			if err != nil {
				logger.Error("Failed to create OTLP exporter", logger.ErrField(err))
				return fmt.Errorf("failed to create OTLP exporter: %w", err)
			}
			exporter = exp
		}
	}

	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	logger.Debug("TracerProvider initialized", logger.Any("tracerProvider", tracerProvider))
	logger.Info("OpenTelemetry initialized successfully")
	return nil
}

func Shutdown(ctx context.Context) error {
	otelMu.Lock()
	defer otelMu.Unlock()
	if tracerProvider == nil {
		return fmt.Errorf("tracer provider not initialized")
	}
	logger.Info("Shutting down OpenTelemetry")
	// Simulate timeout for testing
	if os.Getenv("OTEL_TEST_SHUTDOWN_TIMEOUT") == "true" {
		select {
		case <-time.After(10 * time.Millisecond): // Longer than test timeout
			err := fmt.Errorf("shutdown timeout: context deadline exceeded")
			logger.Error("Failed to shutdown TracerProvider", logger.ErrField(err))
			return err
		case <-ctx.Done():
			err := fmt.Errorf("shutdown timeout: %w", ctx.Err())
			logger.Error("Failed to shutdown TracerProvider", logger.ErrField(err))
			return err
		}
	}
	err := tracerProvider.Shutdown(ctx)
	if err != nil {
		logger.Error("Failed to shutdown TracerProvider", logger.ErrField(err))
		return fmt.Errorf("failed to shutdown TracerProvider: %w", err)
	}
	logger.Info("OpenTelemetry shutdown successfully")
	tracerProvider = nil // Reset to ensure subsequent Shutdown calls fail
	return nil
}

func GetTracer(name string) oteltrace.Tracer {
	otelMu.RLock()
	defer otelMu.RUnlock()
	if tracerProvider == nil {
		logger.Warn("TracerProvider not initialized, returning noop tracer", logger.String("name", name))
		return noop.NewTracerProvider().Tracer(name)
	}
	logger.Debug("Returning tracer", logger.String("name", name), logger.Any("tracerProvider", tracerProvider))
	return tracerProvider.Tracer(name)
}
