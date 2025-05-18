package main

import (
	"context"

	config "github.com/T-Prohmpossadhorn/go-core-config"
	logger "github.com/T-Prohmpossadhorn/go-core-logger"
	"github.com/T-Prohmpossadhorn/go-core-otel"
)

func main() {
	// Initialize config
	cfg, err := config.New(config.WithEnv("CONFIG"))
	if err != nil {
		panic("Failed to initialize config: " + err.Error())
	}

	// Initialize logger
	if err := logger.Init(); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
	defer logger.Sync()

	// Initialize otel
	if err := otel.Init(cfg); err != nil {
		panic("Failed to initialize otel: " + err.Error())
	}
	defer otel.Shutdown(context.Background())

	// Start span without explicitly fetching a tracer
	ctx, span := otel.StartSpan(context.Background(), "example", "example-span")
	defer span.End()

	// Log with span context
	logger.InfoContext(ctx, "Processing request",
		logger.String("request_id", "abc123"),
		logger.Any("params", map[string]string{"key": "value"}),
	)
}
