package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/project-kessel/parsec/internal/probe"
	"github.com/project-kessel/parsec/internal/service"
)

// NewObserver creates an application observer from configuration.
// This is a convenience wrapper that creates its own logger from cfg.
func NewObserver(cfg *ObservabilityConfig) (service.ApplicationObserver, error) {
	return NewObserverWithLogger(cfg, NewLogger(cfg))
}

// NewObserverWithLogger creates an application observer using the provided logger.
// Use this when you want the observer to share a logger with other components.
func NewObserverWithLogger(cfg *ObservabilityConfig, logger *slog.Logger) (service.ApplicationObserver, error) {
	if cfg == nil {
		// Default to no-op observer if not configured
		return &service.NoOpApplicationObserver{}, nil
	}

	switch cfg.Type {
	case "logging":
		return probe.NewLoggingObserverWithConfig(probe.LoggingObserverConfig{
			Logger: logger,
		}), nil
	case "noop", "":
		return &service.NoOpApplicationObserver{}, nil
	case "composite":
		return newCompositeObserver(cfg)
	default:
		return nil, fmt.Errorf("unknown observability type: %s (supported: logging, noop, composite)", cfg.Type)
	}
}

// NewLogger creates a structured logger from the observability configuration.
// Returns slog.Default() if cfg is nil.
func NewLogger(cfg *ObservabilityConfig) *slog.Logger {
	if cfg == nil {
		return slog.Default()
	}

	defaultLevel := parseLogLevel(cfg.LogLevel)
	handler := createEventFilteringHandler(cfg, defaultLevel)
	return slog.New(handler)
}

// newCompositeObserver creates a composite observer that delegates to multiple observers
func newCompositeObserver(cfg *ObservabilityConfig) (service.ApplicationObserver, error) {
	if len(cfg.Observers) == 0 {
		return nil, fmt.Errorf("composite observer requires at least one sub-observer")
	}

	var observers []service.ApplicationObserver
	for i, subCfg := range cfg.Observers {
		observer, err := NewObserver(&subCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create observer %d: %w", i, err)
		}
		observers = append(observers, observer)
	}

	return service.NewCompositeObserver(observers...), nil
}

// createEventFilteringHandler creates a handler that filters log events based on the event attribute
func createEventFilteringHandler(cfg *ObservabilityConfig, defaultLevel slog.Level) slog.Handler {
	// Create base handler
	baseHandler := createHandler(cfg.LogFormat, defaultLevel)

	// Build event-specific level map
	eventLevels := make(map[string]slog.Level)

	if cfg.TokenIssuance != nil {
		if cfg.TokenIssuance.Enabled != nil && !*cfg.TokenIssuance.Enabled {
			eventLevels["token_issuance"] = slog.Level(1000) // Effectively disabled
		} else if cfg.TokenIssuance.LogLevel != "" {
			eventLevels["token_issuance"] = parseLogLevel(cfg.TokenIssuance.LogLevel)
		}
	}

	if cfg.TokenExchange != nil {
		if cfg.TokenExchange.Enabled != nil && !*cfg.TokenExchange.Enabled {
			eventLevels["token_exchange"] = slog.Level(1000) // Effectively disabled
		} else if cfg.TokenExchange.LogLevel != "" {
			eventLevels["token_exchange"] = parseLogLevel(cfg.TokenExchange.LogLevel)
		}
	}

	if cfg.AuthzCheck != nil {
		if cfg.AuthzCheck.Enabled != nil && !*cfg.AuthzCheck.Enabled {
			eventLevels["authz_check"] = slog.Level(1000) // Effectively disabled
		} else if cfg.AuthzCheck.LogLevel != "" {
			eventLevels["authz_check"] = parseLogLevel(cfg.AuthzCheck.LogLevel)
		}
	}

	return &eventFilteringHandler{
		next:         baseHandler,
		eventLevels:  eventLevels,
		defaultLevel: defaultLevel,
	}
}

// eventFilteringHandler wraps a handler and filters based on the event attribute
type eventFilteringHandler struct {
	next         slog.Handler
	eventLevels  map[string]slog.Level
	defaultLevel slog.Level
}

func (h *eventFilteringHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// For now, use default level check
	// The actual filtering happens in Handle
	return level >= h.defaultLevel
}

func (h *eventFilteringHandler) Handle(ctx context.Context, record slog.Record) error {
	// Extract event attribute if present
	var eventName string
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "event" {
			eventName = attr.Value.String()
			return false // Stop iteration
		}
		return true
	})

	// Check event-specific level
	if eventName != "" {
		if eventLevel, ok := h.eventLevels[eventName]; ok {
			if record.Level < eventLevel {
				return nil // Filter out
			}
		}
	}

	return h.next.Handle(ctx, record)
}

func (h *eventFilteringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventFilteringHandler{
		next:         h.next.WithAttrs(attrs),
		eventLevels:  h.eventLevels,
		defaultLevel: h.defaultLevel,
	}
}

func (h *eventFilteringHandler) WithGroup(name string) slog.Handler {
	return &eventFilteringHandler{
		next:         h.next.WithGroup(name),
		eventLevels:  h.eventLevels,
		defaultLevel: h.defaultLevel,
	}
}

// createHandler creates a slog handler based on format and level
func createHandler(format string, level slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(format) {
	case "text":
		return slog.NewTextHandler(os.Stdout, opts)
	case "json", "":
		return slog.NewJSONHandler(os.Stdout, opts)
	default:
		// Default to JSON
		return slog.NewJSONHandler(os.Stdout, opts)
	}
}

// parseLogLevel parses a log level string
func parseLogLevel(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		// Default to info
		return slog.LevelInfo
	}
}
