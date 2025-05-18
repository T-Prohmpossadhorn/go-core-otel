package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/trace"
)

type LoggerConfig struct {
	Level      string
	Output     string
	JSONFormat bool
}

func Init() error { return InitWithConfig(LoggerConfig{}) }

func InitWithConfig(cfg LoggerConfig) error { return nil }

func Sync() {}

type Field struct {
	Key   string
	Value interface{}
}

func Any(key string, value interface{}) Field { return Field{key, value} }
func String(key, value string) Field          { return Field{key, value} }
func ErrField(err error) Field {
	if err != nil {
		return Field{"error", err.Error()}
	}
	return Field{"error", nil}
}

func log(level, msg string, fields []Field) error {
	entry := map[string]interface{}{
		"level": level,
		"msg":   msg,
	}
	for _, f := range fields {
		entry[f.Key] = f.Value
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}

func logContext(ctx context.Context, level, msg string, fields []Field) error {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		fields = append(fields,
			Field{"trace_id", span.SpanContext().TraceID().String()},
			Field{"span_id", span.SpanContext().SpanID().String()},
		)
	}
	return log(level, msg, fields)
}

func Info(msg string, fields ...Field) error { return log("info", msg, fields) }
func InfoContext(ctx context.Context, msg string, fields ...Field) error {
	return logContext(ctx, "info", msg, fields)
}
func Debug(msg string, fields ...Field) error { return log("debug", msg, fields) }
func Warn(msg string, fields ...Field) error  { return log("warn", msg, fields) }
func Error(msg string, fields ...Field) error { return log("error", msg, fields) }
