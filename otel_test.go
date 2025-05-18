package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	config "github.com/T-Prohmpossadhorn/go-core-config"
	"github.com/T-Prohmpossadhorn/go-core-logger"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// syncWriter is a thread-safe writer for capturing logs
type syncWriter struct {
	buf *bytes.Buffer
	mu  sync.Mutex
}

func (sw *syncWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.buf.Write(p)
}

func setupLogger(t *testing.T) (*syncWriter, *os.File, func()) {
	var logBuf bytes.Buffer
	logWriter := &syncWriter{buf: &logBuf}
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w
	go func() {
		_, _ = logBuf.ReadFrom(r)
		time.Sleep(200 * time.Millisecond) // Ensure all logs are read
		r.Close()
	}()
	err = logger.InitWithConfig(logger.LoggerConfig{
		Level:      "info",
		Output:     "console",
		JSONFormat: true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}
	return logWriter, w, func() {
		logger.Sync()
		time.Sleep(200 * time.Millisecond) // Ensure logs are flushed
		w.Close()
		os.Stdout = originalStdout
	}
}

func getLogs(writer *syncWriter) string {
	logger.Sync()
	time.Sleep(200 * time.Millisecond) // Ensure logs are flushed
	writer.mu.Lock()
	defer writer.mu.Unlock()
	logs := writer.buf.String()
	return logs
}

func resetLogs(writer *syncWriter) {
	logger.Sync()
	time.Sleep(200 * time.Millisecond) // Ensure logs are flushed
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.buf.Reset()
}

func TestOTel(t *testing.T) {
	cfg, err := config.New(config.WithEnv("CONFIG"))
	assert.NoError(t, err)
	t.Logf("Config loaded: %+v", cfg)

	t.Run("DebugEnvironment", func(t *testing.T) {
		t.Logf("Config: %+v", cfg)
		t.Logf("Environment: %+v", os.Environ())
		t.Logf("Stdout: %+v", os.Stdout)
		t.Logf("Stderr: %+v", os.Stderr)
	})

	t.Run("TestLogger", func(t *testing.T) {
		logWriter, _, cleanup := setupLogger(t)
		defer cleanup()
		resetLogs(logWriter)

		err := logger.Info("Test log")
		assert.NoError(t, err)
		logString := getLogs(logWriter)
		t.Logf("Logger output: %s", logString)
		assert.Contains(t, logString, "Test log")
	})

	t.Run("InitializationAndSpanManagement", func(t *testing.T) {
		logWriter, _, cleanup := setupLogger(t)
		defer cleanup()
		resetLogs(logWriter)

		// Reset global state
		os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
		os.Unsetenv("OTEL_TEST_OTLP_FAIL")
		os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
		otelMu.Lock()
		tracerProvider = nil
		otelMu.Unlock()

		// Log environment
		t.Logf("Environment OTEL_TEST_SHUTDOWN_TIMEOUT: %s", os.Getenv("OTEL_TEST_SHUTDOWN_TIMEOUT"))
		t.Logf("Environment OTEL_TEST_OTLP_FAIL: %s", os.Getenv("OTEL_TEST_OTLP_FAIL"))
		t.Logf("Environment OTEL_TEST_STDOUT_FAIL: %s", os.Getenv("OTEL_TEST_STDOUT_FAIL"))
		t.Logf("Stdout: %+v", os.Stdout)

		err := Init(cfg)
		if err != nil {
			t.Logf("Init failed: %v", err)
			t.Fatalf("Init failed: %v", err)
		}

		logString := getLogs(logWriter)
		t.Logf("Log output after init: %s", logString)

		var logEntry map[string]interface{}
		lines := strings.Split(strings.TrimSpace(logString), "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
				if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
					t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
					continue
				}
				if logEntry != nil {
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "success log should be present")

		ctx, span := StartSpan(context.Background(), "test-otel", "test-span")
		defer span.End()

		err = logger.InfoContext(ctx, "Test OTEL integration",
			logger.String("key", "value"),
		)
		assert.NoError(t, err)

		logString = getLogs(logWriter)
		lines = strings.Split(strings.TrimSpace(logString), "\n")
		found = false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "test otel integration") {
				if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
					t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
					continue
				}
				if logEntry != nil {
					assert.Equal(t, "value", logEntry["key"])
					assert.NotEmpty(t, logEntry["trace_id"], "trace_id should be present")
					assert.NotEmpty(t, logEntry["span_id"], "span_id should be present")
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "log entry should be present")

		spanCtx := span.SpanContext()
		assert.True(t, spanCtx.IsValid(), "span context should be valid")

		err = Shutdown(context.Background())
		assert.NoError(t, err)

		logString = getLogs(logWriter)
		t.Logf("Log output after shutdown: %s", logString)
		lines = strings.Split(strings.TrimSpace(logString), "\n")
		found = false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "shutting down opentelemetry") {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "shutdown log should be present")
	})

	t.Run("NoopTracerWhenNotInitialized", func(t *testing.T) {
		logWriter, _, cleanup := setupLogger(t)
		defer cleanup()
		resetLogs(logWriter)

		// Reset global state
		os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
		os.Unsetenv("OTEL_TEST_OTLP_FAIL")
		os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
		otelMu.Lock()
		tracerProvider = nil
		otelMu.Unlock()

		ctx, span := StartSpan(context.Background(), "test-otel", "test-span")
		defer span.End()

		err := logger.InfoContext(ctx, "Test noop tracer",
			logger.String("key", "value"),
		)
		assert.NoError(t, err)

		logString := getLogs(logWriter)
		t.Logf("Log output: %s", logString)

		var logEntry map[string]interface{}
		lines := strings.Split(strings.TrimSpace(logString), "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, "Test noop tracer") {
				if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
					t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
					continue
				}
				if logEntry != nil {
					assert.Equal(t, "value", logEntry["key"])
					_, hasTraceID := logEntry["trace_id"]
					_, hasSpanID := logEntry["span_id"]
					assert.False(t, hasTraceID, "trace_id should not be present")
					assert.False(t, hasSpanID, "span_id should not be present")
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "log entry should be present")

		spanCtx := span.SpanContext()
		assert.False(t, spanCtx.IsValid(), "span context should be invalid")

		lines = strings.Split(strings.TrimSpace(logString), "\n")
		found = false
		for _, line := range lines {
			if strings.Contains(line, "TracerProvider not initialized, returning noop tracer") {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "noop tracer warning log should be present")
	})

	t.Run("CustomConfig", func(t *testing.T) {
		logWriter, _, cleanup := setupLogger(t)
		defer cleanup()
		resetLogs(logWriter)

		// Reset global state
		os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
		os.Unsetenv("OTEL_TEST_OTLP_FAIL")
		os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
		otelMu.Lock()
		tracerProvider = nil
		otelMu.Unlock()

		otelCfg := OTelConfig{
			Endpoint: "otel-collector:4317",
			Insecure: false,
		}
		err := InitWithConfig(cfg, otelCfg)
		assert.NoError(t, err)

		logString := getLogs(logWriter)
		t.Logf("Log output after init: %s", logString)

		var logEntry map[string]interface{}
		lines := strings.Split(strings.TrimSpace(logString), "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
				if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
					t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
					continue
				}
				if logEntry != nil {
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "success log should be present")

		ctx, span := StartSpan(context.Background(), "test-otel", "test-span")
		defer span.End()

		err = logger.InfoContext(ctx, "Test custom config",
			logger.String("key", "value"),
		)
		assert.NoError(t, err)

		logString = getLogs(logWriter)
		lines = strings.Split(strings.TrimSpace(logString), "\n")
		found = false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "test custom config") {
				if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
					t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
					continue
				}
				if logEntry != nil {
					assert.Equal(t, "value", logEntry["key"])
					assert.NotEmpty(t, logEntry["trace_id"], "trace_id should be present")
					assert.NotEmpty(t, logEntry["span_id"], "span_id should be present")
					found = true
					break
				}
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "log entry should be present")

		spanCtx := span.SpanContext()
		assert.True(t, spanCtx.IsValid(), "span context should be valid")

		err = Shutdown(context.Background())
		assert.NoError(t, err)

		logString = getLogs(logWriter)
		t.Logf("Log output after shutdown: %s", logString)
		lines = strings.Split(strings.TrimSpace(logString), "\n")
		found = false
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "shutting down opentelemetry") {
				found = true
				break
			}
		}
		if !found {
			t.Logf("Log output: %s", logString)
		}
		assert.True(t, found, "shutdown log should be present")
	})

	t.Run("AdditionalCoverage", func(t *testing.T) {
		// Reset global state
		os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
		os.Unsetenv("OTEL_TEST_OTLP_FAIL")
		os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
		otelMu.Lock()
		tracerProvider = nil
		otelMu.Unlock()

		t.Run("InvalidEndpoint", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			otelCfg := OTelConfig{
				Endpoint: "invalid.invalid:4317",
				Insecure: true,
			}
			errChan := make(chan error, 1)
			go func() {
				errChan <- InitWithConfig(cfg, otelCfg)
			}()
			select {
			case err := <-errChan:
				assert.Error(t, err, "should fail with invalid endpoint")
				assert.Contains(t, strings.ToLower(err.Error()), "failed to validate endpoint", "error message should indicate validation failure")
			case <-time.After(5 * time.Second):
				t.Fatal("InitWithConfig timed out")
			}

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "invalid endpoint") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("InvalidPort", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			otelCfg := OTelConfig{
				Endpoint: "localhost:0",
				Insecure: true,
			}
			errChan := make(chan error, 1)
			go func() {
				errChan <- InitWithConfig(cfg, otelCfg)
			}()
			select {
			case err := <-errChan:
				assert.Error(t, err, "should fail with invalid port")
				assert.Contains(t, strings.ToLower(err.Error()), "failed to validate endpoint", "error message should indicate validation failure")
			case <-time.After(5 * time.Second):
				t.Fatal("InitWithConfig timed out")
			}

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "invalid endpoint") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("MalformedEndpoint", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			otelCfg := OTelConfig{
				Endpoint: "invalid:endpoint",
				Insecure: true,
			}
			errChan := make(chan error, 1)
			go func() {
				errChan <- InitWithConfig(cfg, otelCfg)
			}()
			select {
			case err := <-errChan:
				assert.Error(t, err, "should fail with malformed endpoint")
				assert.Contains(t, strings.ToLower(err.Error()), "failed to validate endpoint", "error message should indicate validation failure")
			case <-time.After(5 * time.Second):
				t.Fatal("InitWithConfig timed out")
			}

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "invalid endpoint") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("SecureEndpointWithoutCredentials", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			os.Setenv("OTEL_TEST_OTLP_FAIL", "true")
			defer os.Unsetenv("OTEL_TEST_OTLP_FAIL")

			otelCfg := OTelConfig{
				Endpoint: "localhost:4317",
				Insecure: false,
			}
			errChan := make(chan error, 1)
			go func() {
				errChan <- InitWithConfig(cfg, otelCfg)
			}()
			select {
			case err := <-errChan:
				assert.Error(t, err, "should fail with forced OTLP failure")
				assert.Contains(t, strings.ToLower(err.Error()), "failed to create otlp exporter", "error message should indicate OTLP failure")
			case <-time.After(5 * time.Second):
				t.Fatal("InitWithConfig timed out")
			}

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "failed to create otlp exporter") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("InsecureOptionExplicit", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			otelCfg := OTelConfig{
				Endpoint: "localhost:4317",
				Insecure: true,
			}
			err := InitWithConfig(cfg, otelCfg)
			assert.NoError(t, err, "should succeed with insecure endpoint")

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "success log should be present")

			err = Shutdown(context.Background())
			assert.NoError(t, err)

			logString = getLogs(logWriter)
			t.Logf("Log output after shutdown: %s", logString)
			lines = strings.Split(strings.TrimSpace(logString), "\n")
			found = false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "shutting down opentelemetry") {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "shutdown log should be present")
		})

		t.Run("StdoutExporterWithEmptyEndpoint", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			otelCfg := OTelConfig{
				Endpoint: "",
				Insecure: true,
			}
			err := InitWithConfig(cfg, otelCfg)
			assert.NoError(t, err, "should succeed with stdout exporter")

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "success log should be present")

			err = Shutdown(context.Background())
			assert.NoError(t, err)

			logString = getLogs(logWriter)
			t.Logf("Log output after shutdown: %s", logString)
			lines = strings.Split(strings.TrimSpace(logString), "\n")
			found = false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "shutting down opentelemetry") {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "shutdown log should be present")
		})

		t.Run("StdoutExporterFailure", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			os.Setenv("OTEL_TEST_STDOUT_FAIL", "true")
			defer os.Unsetenv("OTEL_TEST_STDOUT_FAIL")

			otelCfg := OTelConfig{
				Endpoint: "",
				Insecure: true,
			}
			err := InitWithConfig(cfg, otelCfg)
			assert.Error(t, err, "should fail with simulated stdout exporter error")
			assert.Contains(t, strings.ToLower(err.Error()), "failed to create stdouttrace exporter", "error message should indicate stdout failure")

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "failed to create stdouttrace exporter") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("ConcurrentAccess", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			os.Setenv("OTEL_TEST_MOCK_EXPORTER", "true")
			defer os.Unsetenv("OTEL_TEST_MOCK_EXPORTER")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			var wg sync.WaitGroup
			const numGoroutines = 5 // Reduced from 10 to optimize runtime

			for i := 0; i < numGoroutines; i++ {
				err := Init(cfg)
				if err != nil {
					t.Errorf("sequential Init failed: %v", err)
				}
			}
			start := time.Now()
			for time.Since(start) < 20*time.Millisecond {
				otelMu.RLock()
				if tracerProvider != nil {
					otelMu.RUnlock()
					break
				}
				otelMu.RUnlock()
				time.Sleep(5 * time.Millisecond)
			}

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, span := StartSpan(context.Background(), "test-tracer-"+string(rune(i)), "test-span")
					if !span.SpanContext().IsValid() && tracerProvider != nil {
						t.Errorf("concurrent GetTracer returned invalid span for tracer %d; tracerProvider: %v", i, tracerProvider)
					}
					span.End()
					_ = ctx // Use ctx to avoid unused variable error
				}(i)
			}

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := Shutdown(context.Background())
					if err != nil && !strings.Contains(err.Error(), "tracer provider not initialized") {
						t.Errorf("concurrent Shutdown failed: %v", err)
					}
				}()
			}

			wg.Wait()

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "at least one initialization log should be present")

			err := Init(cfg)
			assert.NoError(t, err)
		})

		t.Run("ShutdownWithCanceledContext", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			err := Init(cfg)
			if err != nil {
				t.Logf("Init failed: %v", err)
				t.Fatalf("Init failed: %v", err)
			}

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err = Shutdown(ctx)
			assert.Error(t, err, "should fail with canceled context")
			assert.Contains(t, strings.ToLower(err.Error()), "failed to shutdown tracerprovider", "error message should indicate shutdown failure")

			logString = getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "failed to shutdown tracerprovider") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")

			err = Shutdown(context.Background())
			assert.NoError(t, err)
		})

		t.Run("GetTracerEdgeCases", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			tracer := GetTracer("")
			_, span := tracer.Start(context.Background(), "test-span")
			defer span.End()
			assert.False(t, span.SpanContext().IsValid(), "empty tracer name should return noop tracer")

			tracer = GetTracer("!@#$%^&*")
			_, span = tracer.Start(context.Background(), "test-span")
			defer span.End()
			assert.False(t, span.SpanContext().IsValid(), "special character tracer name should return noop tracer")

			err := Init(cfg)
			if err != nil {
				t.Logf("Init failed: %v", err)
				t.Fatalf("Init failed: %v", err)
			}

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			tracer = GetTracer("")
			_, span = tracer.Start(context.Background(), "test-span")
			defer span.End()
			assert.True(t, span.SpanContext().IsValid(), "empty tracer name should return valid tracer after initialization")

			logString = getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(line, "TracerProvider not initialized, returning noop tracer") {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "noop tracer warning log should be present")

			err = Shutdown(context.Background())
			assert.NoError(t, err)
		})

		t.Run("TracePropagation", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			err := Init(cfg)
			if err != nil {
				t.Logf("Init failed: %v", err)
				t.Fatalf("Init failed: %v", err)
			}

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			tracer := GetTracer("test-propagation")
			ctx, span := tracer.Start(context.Background(), "test-span")
			defer span.End()

			t.Logf("Trace context created: %v", ctx)

			member, err := baggage.NewMember("key", "value")
			assert.NoError(t, err)
			bag, err := baggage.New(member)
			assert.NoError(t, err)

			carrier := make(map[string]string)
			propagator := otel.GetTextMapPropagator()
			propagator.Inject(baggage.ContextWithBaggage(ctx, bag), propagation.MapCarrier(carrier))

			assert.NotEmpty(t, carrier["traceparent"], "traceparent should be present in carrier")
			assert.NotEmpty(t, carrier["baggage"], "baggage should be present in carrier")
			assert.Contains(t, carrier["baggage"], "key=value", "baggage should contain key=value")

			newCtx := propagator.Extract(context.Background(), propagation.MapCarrier(carrier))
			newSpan := oteltrace.SpanFromContext(newCtx)
			assert.True(t, newSpan.SpanContext().IsValid(), "extracted span context should be valid")
			assert.Equal(t, span.SpanContext().TraceID(), newSpan.SpanContext().TraceID(), "trace IDs should match")

			extractedBaggage := baggage.FromContext(newCtx)
			memberValue := extractedBaggage.Member("key")
			assert.NotEmpty(t, memberValue, "baggage key should be present")
			assert.Equal(t, "value", memberValue.Value(), "baggage value should match")

			logString = getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "opentelemetry initialized successfully") {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "initialization log should be present")

			err = Shutdown(context.Background())
			assert.NoError(t, err)
		})

		t.Run("InitWithInvalidConfigEndpoint", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			cfg, err := config.New(
				config.WithDefault(map[string]interface{}{
					"otel_endpoint": "invalid.invalid:4317",
					"otel_insecure": true,
				}),
			)
			assert.NoError(t, err)

			errChan := make(chan error, 1)
			go func() {
				errChan <- Init(cfg)
			}()
			select {
			case err := <-errChan:
				assert.Error(t, err, "should fail with invalid config endpoint")
				assert.Contains(t, strings.ToLower(err.Error()), "failed to validate endpoint", "error message should indicate validation failure")
			case <-time.After(5 * time.Second):
				t.Fatal("Init timed out")
			}

			logString := getLogs(logWriter)
			t.Logf("Log output: %s", logString)

			assert.NotContains(t, strings.ToLower(logString), "opentelemetry initialized successfully", "success log should not be present")

			var logEntry map[string]interface{}
			lines := strings.Split(strings.TrimSpace(logString), "\n")
			found := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "invalid endpoint") {
					if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
						t.Logf("Failed to unmarshal log line: %s, error: %v", line, err)
						continue
					}
					if logEntry != nil {
						assert.NotEmpty(t, logEntry["error"], "error field should be present")
						found = true
						break
					}
				}
			}
			if !found {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, found, "error log should be present")
		})

		t.Run("MultipleShutdownAttempts", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			err := Init(cfg)
			if err != nil {
				t.Logf("Init failed: %v", err)
				t.Fatalf("Init failed: %v", err)
			}

			logString := getLogs(logWriter)
			t.Logf("Log output after init: %s", logString)

			err = Shutdown(context.Background())
			assert.NoError(t, err)

			err = Shutdown(context.Background())
			assert.Error(t, err, "should fail as tracerProvider is not initialized")
			assert.Contains(t, strings.ToLower(err.Error()), "tracer provider not initialized", "error message should indicate uninitialized provider")

			logString = getLogs(logWriter)
			t.Logf("Log output after shutdown: %s", logString)

			lines := strings.Split(strings.TrimSpace(logString), "\n")
			foundSuccess := false
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "shutting down opentelemetry") {
					foundSuccess = true
					break
				}
			}
			if !foundSuccess {
				t.Logf("Log output: %s", logString)
			}
			assert.True(t, foundSuccess, "shutdown success log should be present")
		})

		t.Run("ShutdownTimeout", func(t *testing.T) {
			logWriter, _, cleanup := setupLogger(t)
			defer cleanup()
			resetLogs(logWriter)

			// Reset global state
			os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")
			os.Unsetenv("OTEL_TEST_OTLP_FAIL")
			os.Unsetenv("OTEL_TEST_STDOUT_FAIL")
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			// Set environment variable to simulate shutdown timeout
			os.Setenv("OTEL_TEST_SHUTDOWN_TIMEOUT", "true")
			defer os.Unsetenv("OTEL_TEST_SHUTDOWN_TIMEOUT")

			// Initialize otel
			err := Init(cfg)
			if err != nil {
				t.Logf("Init failed: %v", err)
				t.Fatalf("initialization failed: %v", err)
			}

			// Create a context with a short timeout to simulate the failing state
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
			defer cancel()

			// Test shutdown with timeout
			t.Log("Calling Shutdown with timeout context")
			err = Shutdown(ctx)
			t.Logf("Main Shutdown error: %v", err)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "shutdown timeout") || !strings.Contains(strings.ToLower(err.Error()), "context deadline exceeded") {
				t.Fatalf("expected error containing 'shutdown timeout' and 'context deadline exceeded', got %v", err)
			}

			// Reset state for cleanup
			otelMu.Lock()
			tracerProvider = nil
			otelMu.Unlock()

			// Cleanup
			err = Shutdown(context.Background())
			t.Logf("Cleanup Shutdown error: %v", err)
			if err != nil && !strings.Contains(err.Error(), "tracer provider not initialized") {
				t.Fatalf("cleanup Shutdown returned unexpected error: %v", err)
			}
		})
	})
}
