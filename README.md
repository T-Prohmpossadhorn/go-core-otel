# OTel Package

The `otel` package is a lightweight, thread-safe OpenTelemetry setup for distributed tracing in Go applications, part of the `github.com/T-Prohmpossadhorn/go-core` monorepo. It initializes a `TracerProvider` with an OTLP gRPC exporter (or a mock exporter for testing), provides tracers for span management, and integrates with the `config` and `logger` packages for configuration and trace-aware logging. Designed for simplicity and independent usability, it’s ideal for observability in microservices.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Tracing](#basic-tracing)
  - [Integration with Config and Logger](#integration-with-config-and-logger)
  - [Custom Configuration with Context Propagation](#custom-configuration-with-context-propagation)
- [Configuration](#configuration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features
- **OpenTelemetry Tracing**: Initializes a `TracerProvider` with an OTLP gRPC exporter for production or a mock exporter for testing.
- **Span Management**: Offers `GetTracer` and `StartSpan` for easily creating tracers and spans.
- **Thread-Safety**: Uses `sync.RWMutex` for safe concurrent access to the `TracerProvider`.
- **Integration**: Leverages `config` for settings and `logger` for trace-aware logging (`trace_id`, `span_id`).
- **Propagation**: Supports W3C Trace Context and Baggage for distributed tracing.
- **Mock Exporter**: Enables fast, network-free testing with `OTEL_TEST_MOCK_EXPORTER`.
- **Minimal Dependencies**: Relies on OpenTelemetry, `config`, and `logger`.
- **Go 1.24.2**: Compatible with the latest Go version.

## Installation
Install the `otel` package:

```bash
go get github.com/T-Prohmpossadhorn/go-core/otel
```

### Dependencies
- `go.opentelemetry.io/otel@v1.29.0`
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.29.0`
- `go.opentelemetry.io/otel/exporters/stdout/stdouttrace@v1.29.0`
- `go.opentelemetry.io/otel/sdk/trace@v1.29.0`
- `github.com/T-Prohmpossadhorn/go-core-config`
- `github.com/T-Prohmpossadhorn/go-core-logger`
- `github.com/spf13/viper@v1.18.2`

Add to `go.mod`:

```bash
go get go.opentelemetry.io/otel@v1.29.0
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.29.0
go get go.opentelemetry.io/otel/exporters/stdout/stdouttrace@v1.29.0
go get go.opentelemetry.io/otel/sdk/trace@v1.29.0
go get github.com/T-Prohmpossadhorn/go-core-config
go get github.com/T-Prohmpossadhorn/go-core-logger
go get github.com/spf13/viper@v1.18.2
```

### Go Version
Requires Go 1.24.2 or later:

```bash
go version
```

## Usage
The `otel` package provides APIs for initializing OpenTelemetry, managing spans, and integrating with `config` and `logger`. Below are three example scenarios demonstrating its capabilities.

### Basic Tracing
Initialize the `TracerProvider` and create a span for a simple operation:

```go
package main

import (
    "context"
    config "github.com/T-Prohmpossadhorn/go-core-config"
    "github.com/T-Prohmpossadhorn/go-core/otel"
)

func main() {
    // Initialize config
    cfg, err := config.New(config.WithEnv("CONFIG"))
    if err != nil {
        panic("Failed to initialize config: " + err.Error())
    }

    // Initialize otel
    if err := otel.Init(cfg); err != nil {
        panic("Failed to initialize otel: " + err.Error())
    }
    defer otel.Shutdown(context.Background())

    // Create a tracer and start a span
    ctx, span := otel.StartSpan(context.Background(), "example-service", "process-request")
    defer span.End()

    // Simulate work
    println("Processing request...")
}
```

This creates a span named `process-request` under the `example-service` tracer, sent to the OTLP collector (default: `localhost:4317`).

### Integration with Config and Logger
Use `config` to load settings and `logger` for trace-aware logging:

```go
package main

import (
    "context"
    config "github.com/T-Prohmpossadhorn/go-core-config"
    "github.com/T-Prohmpossadhorn/go-core-logger/logger"
    "github.com/T-Prohmpossadhorn/go-core/otel"
)

func main() {
    // Initialize config
    cfg, err := config.New(config.WithEnv("CONFIG"))
    if err != nil {
        panic("Failed to initialize config: " + err.Error())
    }

    // Initialize logger
    if err := logger.InitWithConfig(logger.LoggerConfig{
        Level:      "info",
        Output:     "console",
        JSONFormat: true,
    }); err != nil {
        panic("Failed to initialize logger: " + err.Error())
    }
    defer logger.Sync()

    // Initialize otel
    if err := otel.Init(cfg); err != nil {
        panic("Failed to initialize otel: " + err.Error())
    }
    defer otel.Shutdown(context.Background())

    // Create a span without fetching a tracer
    ctx, span := otel.StartSpan(context.Background(), "user-service", "handle-user-request")
    defer span.End()

    // Log with trace context
    logger.InfoContext(ctx, "Handling user request",
        logger.String("user_id", "12345"),
        logger.String("action", "update_profile"),
    )
}
```

**Output (JSON)**:
```json
{"level":"info","ts":"2025-05-04T12:00:00.000+0700","caller":"main.go:30","msg":"Handling user request","user_id":"12345","action":"update_profile","trace_id":"a8dc554428c5499fdda9a6ef11d952a3","span_id":"f1bf83f6c10bbead"}
```

The log includes `trace_id` and `span_id`, enabling correlation with traces in the OTLP collector.

### Custom Configuration with Context Propagation
Configure a custom endpoint and propagate trace context across services:

```go
package main

import (
    "context"
    config "github.com/T-Prohmpossadhorn/go-core-config"
    "github.com/T-Prohmpossadhorn/go-core-logger/logger"
    "github.com/T-Prohmpossadhorn/go-core/otel"
    "go.opentelemetry.io/otel/baggage"
    "go.opentelemetry.io/otel/propagation"
)

func main() {
    // Initialize config
    cfg, err := config.New(config.WithEnv("CONFIG"))
    if err != nil {
        panic("Failed to initialize config: " + err.Error())
    }

    // Initialize logger
    if err := logger.InitWithConfig(logger.LoggerConfig{
        Level:      "info",
        Output:     "console",
        JSONFormat: true,
    }); err != nil {
        panic("Failed to initialize logger: " + err.Error())
    }
    defer logger.Sync()

    // Initialize otel with custom config
    otelCfg := otel.OTelConfig{
        Endpoint: cfg.GetStringWithDefault("otel_endpoint", "otel-collector:4317"),
        Insecure: cfg.GetBoolWithDefault("otel_insecure", false),
    }
    if err := otel.InitWithConfig(cfg, otelCfg); err != nil {
        panic("Failed to initialize otel: " + err.Error())
    }
    defer otel.Shutdown(context.Background())

    // Create a span for order processing
    ctx, span := otel.StartSpan(context.Background(), "order-service", "process-order")
    defer span.End()

    // Add baggage
    member, _ := baggage.NewMember("order_id", "67890")
    bag, _ := baggage.New(member)
    ctx = baggage.ContextWithBaggage(ctx, bag)

    // Propagate context
    carrier := make(map[string]string)
    otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(carrier))

    // Log with trace context
    logger.InfoContext(ctx, "Processing order",
        logger.Any("carrier", carrier),
    )

    // Simulate downstream service call with extracted context
    downstreamCtx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.MapCarrier(carrier))
    downstreamCtx, downstreamSpan := otel.StartSpan(downstreamCtx, "payment-service", "process-payment")
    defer downstreamSpan.End()

    logger.InfoContext(downstreamCtx, "Processing payment",
        logger.String("order_id", baggage.FromContext(downstreamCtx).Member("order_id").Value()),
    )
}
```

**Output (JSON)**:
```json
{"level":"info","ts":"2025-05-04T12:00:00.000+0700","caller":"main.go:40","msg":"Processing order","carrier":{"baggage":"order_id=67890","traceparent":"00-a8dc554428c5499fdda9a6ef11d952a3-f1bf83f6c10bbead-01"},"trace_id":"a8dc554428c5499fdda9a6ef11d952a3","span_id":"f1bf83f6c10bbead"}
{"level":"info","ts":"2025-05-04T12:00:00.001+0700","caller":"main.go:50","msg":"Processing payment","order_id":"67890","trace_id":"a8dc554428c5499fdda9a6ef11d952a3","span_id":"..."}
```

This demonstrates trace propagation and baggage across services, maintaining the same `trace_id`.

## Configuration
The `otel` package is configured via the `OTelConfig` struct, loaded by the `config` package.

```go
type OTelConfig struct {
    Endpoint string `mapstructure:"otel_endpoint" default:"localhost:4317"`
    Insecure bool   `mapstructure:"otel_insecure" default:"true"`
}
```

### Configuration Options
- **Endpoint**: OTLP collector address (e.g., `otel-collector:4317`).
  - Environment variable: `CONFIG_OTEL_ENDPOINT`
  - Config file key: `otel_endpoint`
  - Default: `localhost:4317`
- **Insecure**: Disable TLS (`true`) or enable TLS (`false`).
  - Environment variable: `CONFIG_OTEL_INSECURE`
  - Config file key: `otel_insecure`
  - Default: `true`

**Example Config File (config.yaml)**:
```yaml
otel_endpoint: "otel-collector:4317"
otel_insecure: false
```

**Example Environment Variable**:
```bash
export CONFIG_OTEL_ENDPOINT=otel-collector:4317
export CONFIG_OTEL_INSECURE=false
```

## Testing
The `otel` package includes comprehensive tests for initialization, termination, span management, and integration with `config` and `logger`. Tests achieve ~89.2% coverage and use a mock exporter for reliable execution.

### Running Tests
Run with verbose output and coverage:

```bash
cd otel
go test -v -cover
```

### Test Environment
- **Mock Exporter**: Tests use `OTEL_TEST_MOCK_EXPORTER=true` for `ConcurrentAccess` to avoid network dependencies, ensuring fast execution (~0.60s).
- **Dependencies**: Requires `config` and `logger` packages from `github.com/T-Prohmpossadhorn/go-core`.
- **Optional Collector**: An OpenTelemetry Collector at `localhost:4317` is not required due to the mock exporter but can be used for real OTLP testing:
  ```bash
  docker run -p 4317:4317 otel/opentelemetry-collector
  ```

### Expected Output
- Valid spans with trace-aware logging:
  ```json
  {"level":"info","ts":"2025-05-04T12:00:00.000+0700","msg":"Test OTEL integration","key":"value","trace_id":"...","span_id":"..."}
  ```
- Noop tracer when uninitialized:
  ```json
  {"level":"info","ts":"2025-05-04T12:00:00.000+0700","msg":"Test noop tracer","key":"value"}
  ```
- Mock exporter usage in `ConcurrentAccess`:
  ```json
  {"level":"info","ts":"2025-05-04T12:00:00.000+0700","msg":"Using mock exporter for testing"}
  ```

## Troubleshooting
### Compilation Errors
- **Verify dependencies**:
  ```bash
  go list -m go.opentelemetry.io/otel
  ```
  Ensure `v1.29.0` for OpenTelemetry packages.
- **Check conflicts**:
  ```bash
  go mod graph | grep opentelemetry
  ```
- **Clear cache**:
  ```bash
  go clean -modcache
  go mod tidy
  ```

### Collector Connection Issues
- **Ensure collector is running** (if not using mock exporter):
  ```bash
  docker run -p 4317:4317 otel/opentelemetry-collector
  ```
- **Verify endpoint**: Check `otel_endpoint` in config or environment (`CONFIG_OTEL_ENDPOINT`).
- **Disable TLS**: Set `otel_insecure: true` if TLS is not configured.

### Missing Trace Fields
- **Verify span context**:
  ```go
  ctx, span := tracer.Start(context.Background(), "example")
  logger.InfoContext(ctx, "Message")
  span.End()
  ```
  Ensure `ctx` includes an active span before logging.
- **Check initialization**: Confirm `otel.Init` or `otel.InitWithConfig` was called successfully.

### Test Failures
- **Mock Exporter**: Ensure `OTEL_TEST_MOCK_EXPORTER=true` for `ConcurrentAccess` to avoid network timeouts.
- **Dependencies**: Verify `config` and `logger` packages are correctly installed.
- **Logs**: Check test logs for errors (e.g., `Failed to create OTLP exporter`).

## Contributing
Contributions are welcome! Follow these steps:
1. Fork `github.com/T-Prohmpossadhorn/go-core`.
2. Create a feature branch (e.g., `feature/add-metrics`).
3. Implement changes and add tests in the `otel` package.
4. Ensure tests pass:
   ```bash
   cd otel
   go test -v -cover
   ```
5. Format code with `gofmt` and lint with `golint`.
6. Submit a pull request with a clear description.

### Development Setup
```bash
git clone https://github.com/T-Prohmpossadhorn/go-core.git
cd go-core/otel
go mod tidy
```

### Code Style
- Use `gofmt` for formatting.
- Run `golint` for linting.
- Write clear, commented code.
- Ensure new functionality is covered by tests achieving ~89% coverage.

## License
MIT License. See `LICENSE` file in the repository.