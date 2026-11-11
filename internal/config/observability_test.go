package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

func boolPtr(b bool) *bool { return &b }

// providerWithObs is a test helper that builds a Provider with the given
// ObservabilityConfig and returns its Observer.
func providerWithObs(t *testing.T, cfg *ObservabilityConfig) *Provider {
	t.Helper()
	return NewProvider(&Config{Observability: cfg})
}

func TestProvider_Observer_NilConfig_ReturnsNoop(t *testing.T) {
	p := providerWithObs(t, nil)
	obs, err := p.Observer()
	require.NoError(t, err)
	require.NotNil(t, obs)

	ctx := context.Background()
	_, probe := obs.CacheFetchStarted(ctx, "ds")
	probe.CacheHit()
}

func TestProvider_Observer_NoopType(t *testing.T) {
	for _, typ := range []string{"noop", ""} {
		t.Run("type="+typ, func(t *testing.T) {
			p := providerWithObs(t, &ObservabilityConfig{Type: typ})
			obs, err := p.Observer()
			require.NoError(t, err)
			require.NotNil(t, obs)

			ctx := context.Background()
			_, probe := obs.RotationCheckStarted(ctx)
			probe.RotationCompleted("slot")
		})
	}
}

func TestProvider_Observer_UnknownType_ReturnsError(t *testing.T) {
	p := providerWithObs(t, &ObservabilityConfig{Type: "jaeger"})
	_, err := p.Observer()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown observability type")
}

func TestProvider_Observer_CompositeEmpty_ReturnsError(t *testing.T) {
	p := providerWithObs(t, &ObservabilityConfig{
		Type:      "composite",
		Observers: nil,
	})
	_, err := p.Observer()
	assert.Error(t, err)
}

func TestProvider_Observer_MetricsType_ConfiguresHTTPMux(t *testing.T) {
	p := providerWithObs(t, &ObservabilityConfig{Type: "metrics"})
	obs, err := p.Observer()
	require.NoError(t, err)
	require.NotNil(t, obs)

	assert.Equal(t, "/metrics", p.BootstrapFields()["metrics_endpoint"])

	mux := http.NewServeMux()
	obs.ConfigureHTTPMux(mux)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "metrics endpoint should be registered")
}

func TestProvider_Observer_CompositeWithMetrics_ConfiguresHTTPMux(t *testing.T) {
	p := providerWithObs(t, &ObservabilityConfig{
		Type: "composite",
		Observers: []ObservabilityConfig{
			{Type: "noop"},
			{Type: "metrics"},
		},
	})
	obs, err := p.Observer()
	require.NoError(t, err)
	require.NotNil(t, obs)

	mux := http.NewServeMux()
	obs.ConfigureHTTPMux(mux)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "composite with metrics child should register /metrics")
}

func TestProvider_Observer_NoopType_NoBootstrapFields(t *testing.T) {
	p := providerWithObs(t, &ObservabilityConfig{Type: "noop"})
	_, err := p.Observer()
	require.NoError(t, err)

	assert.Empty(t, p.BootstrapFields())
}

func TestNewLoggingObserver_ProducesOutput(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	obs, err := newLoggingObserver(&ObservabilityConfig{Type: "logging"}, logCtx)
	require.NoError(t, err)
	require.NotNil(t, obs)

	ctx := context.Background()
	_, p := obs.CacheFetchStarted(ctx, "test-ds")
	p.FetchFailed(errors.New("timeout"))

	assert.Contains(t, buf.String(), "data source fetch failed")
	assert.Contains(t, buf.String(), `"datasource":"test-ds"`)
}

func TestNewAuditObserverAlwaysProducesJSONAtInfo(t *testing.T) {
	var buf bytes.Buffer
	logCtx := LoggerContext{
		Logger: zerolog.New(&buf).Level(zerolog.ErrorLevel),
		Writer: &buf,
	}
	p := NewProvider(&Config{TrustDomain: "td.example"})

	obs, err := p.newAuditObserver(&ObservabilityConfig{
		Type:                "audit",
		AllowedMetadataKeys: []string{"cache_status"},
	}, logCtx)
	require.NoError(t, err)
	ctx := request.WithID(context.Background(), "request-1")
	_, probe := obs.AuthzCheckStarted(ctx)
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	var record map[string]any
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.NotEmpty(t, lines)
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &record))
	assert.Equal(t, "parsec_request", record["event"])
	assert.Equal(t, "info", record["level"])
	assert.Equal(t, "success", record["outcome"])
}

func TestNewAuditObserverEmitsOneTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logCtx := LoggerContext{Logger: zerolog.New(&buf), Writer: &buf}
	p := NewProvider(&Config{TrustDomain: "td.example"})

	obs, err := p.newAuditObserver(&ObservabilityConfig{
		Type:                "audit",
		AllowedMetadataKeys: []string{"cache_status"},
	}, logCtx)
	require.NoError(t, err)
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-time"))
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		require.Equal(t, 1, strings.Count(line, `"time":`))
	}
}

func TestNewAuditObserverWarnsWhenNoAllowlistConfigured(t *testing.T) {
	var buf bytes.Buffer
	logCtx := LoggerContext{Logger: zerolog.New(&buf), Writer: &buf}
	p := NewProvider(&Config{TrustDomain: "td.example"})

	_, err := p.newAuditObserver(&ObservabilityConfig{Type: "audit"}, logCtx)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "audit_metadata_keys not configured")
}

func TestAuditObserverEventPrefixValidation(t *testing.T) {
	custom := "custom."
	p := providerWithObs(t, &ObservabilityConfig{Type: "audit", EventPrefix: &custom})
	_, err := p.Observer()
	require.NoError(t, err)

	invalid := "bad prefix/"
	p = providerWithObs(t, &ObservabilityConfig{Type: "audit", EventPrefix: &invalid})
	_, err = p.Observer()
	require.ErrorContains(t, err, "invalid audit event prefix")
}

func TestEffectiveEventPrefix(t *testing.T) {
	child := "child."
	top := "top."

	t.Run("child overrides parent", func(t *testing.T) {
		got := effectiveEventPrefix(&ObservabilityConfig{EventPrefix: &child}, &ObservabilityConfig{EventPrefix: &top})
		require.NotNil(t, got)
		assert.Equal(t, child, *got)
	})

	t.Run("falls back to parent when child unset", func(t *testing.T) {
		got := effectiveEventPrefix(&ObservabilityConfig{}, &ObservabilityConfig{EventPrefix: &top})
		require.NotNil(t, got)
		assert.Equal(t, top, *got)
	})

	t.Run("nil when neither set", func(t *testing.T) {
		got := effectiveEventPrefix(&ObservabilityConfig{}, &ObservabilityConfig{})
		assert.Nil(t, got)
	})

	t.Run("nil top-level config", func(t *testing.T) {
		got := effectiveEventPrefix(&ObservabilityConfig{}, nil)
		assert.Nil(t, got)
	})
}

// TestProvider_Observer_CompositeAudit_HonorsTopLevelEventPrefix guards
// against a regression where a `type: composite` observer's top-level
// event_prefix (and the --observability-event-prefix flag that sets it) was
// silently ignored because the child `- type: audit` entry was consulted
// exclusively.
func TestProvider_Observer_CompositeAudit_HonorsTopLevelEventPrefix(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)
	custom := "custom_"

	p := providerWithObs(t, &ObservabilityConfig{
		Type:        "composite",
		EventPrefix: &custom,
		Observers:   []ObservabilityConfig{{Type: "audit"}},
	})
	p.logCtx = &logCtx

	obs, err := p.Observer()
	require.NoError(t, err)
	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-prefix"))
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	assert.Contains(t, buf.String(), `"event":"custom_request"`)
}

func TestProvider_Observer_RejectsMoreThanOneAuditObserver(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	p := providerWithObs(t, &ObservabilityConfig{
		Type: "composite",
		Observers: []ObservabilityConfig{
			{Type: "audit"},
			{Type: "composite", Observers: []ObservabilityConfig{{Type: "audit"}}},
		},
	})
	p.logCtx = &logCtx

	_, err := p.Observer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 audit observers configured; at most one is supported")
}

func TestAllowedMetadataKeys(t *testing.T) {
	p := NewProvider(&Config{})

	t.Run("child overrides parent", func(t *testing.T) {
		p.config.Observability = &ObservabilityConfig{AllowedMetadataKeys: []string{"parent_key"}}
		keys := p.allowedMetadataKeys(&ObservabilityConfig{AllowedMetadataKeys: []string{"child_key"}})
		assert.Equal(t, map[string]bool{"child_key": true}, keys)
	})

	t.Run("falls back to parent when child unset", func(t *testing.T) {
		p.config.Observability = &ObservabilityConfig{AllowedMetadataKeys: []string{"parent_key"}}
		keys := p.allowedMetadataKeys(&ObservabilityConfig{})
		assert.Equal(t, map[string]bool{"parent_key": true}, keys)
	})

	t.Run("empty non-nil when neither set", func(t *testing.T) {
		p.config.Observability = &ObservabilityConfig{}
		keys := p.allowedMetadataKeys(&ObservabilityConfig{})
		assert.NotNil(t, keys, "must return non-nil empty map (reject-all) when no allowlist configured")
		assert.Empty(t, keys)
	})
}

func TestProvider_Observer_CompositeLogging_FansOut(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	p := providerWithObs(t, &ObservabilityConfig{
		Type: "composite",
		Observers: []ObservabilityConfig{
			{Type: "logging"},
			{Type: "logging"},
		},
	})
	p.logCtx = &logCtx

	obs, err := p.Observer()
	require.NoError(t, err)
	require.NotNil(t, obs)

	obs.GRPCServeFailed(errors.New("bind error"))

	output := buf.String()
	first := strings.Index(output, "gRPC server error")
	require.NotEqual(t, -1, first, "expected at least one gRPC server error log")
	second := strings.Index(output[first+1:], "gRPC server error")
	assert.NotEqual(t, -1, second, "composite with 2 logging children should log twice")
}

func TestNewLoggingObserver_InvalidEventConfig_ReturnsError(t *testing.T) {
	logCtx := jsonLogCtx(&bytes.Buffer{})
	_, err := newLoggingObserver(&ObservabilityConfig{
		Type:          "logging",
		TokenIssuance: &EventLoggingConfig{LogLevel: "verbose"},
	}, logCtx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log_level")
}

// jsonLogCtx builds a LoggerContext that writes JSON to buf.
// Writer is set to the raw buf so format overrides work correctly.
func jsonLogCtx(buf *bytes.Buffer) LoggerContext {
	return LoggerContext{
		Logger: zerolog.New(buf).With().Timestamp().Logger().Level(zerolog.InfoLevel),
		Writer: buf,
	}
}

func TestEventLogger_NilConfig_InheritsBase(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	logger, err := EventLogger(logCtx, "test_event", nil)
	require.NoError(t, err)
	logger.Info().Msg("hello")

	assert.Contains(t, buf.String(), `"event":"test_event"`)
	assert.Contains(t, buf.String(), `"message":"hello"`)
}

func TestEventLogger_LevelAndEnabled(t *testing.T) {
	tests := []struct {
		name      string
		baseLevel zerolog.Level
		eventCfg  *EventLoggingConfig
		emitLevel zerolog.Level
		wantEmpty bool
	}{
		{
			name:      "nil config inherits base level",
			baseLevel: zerolog.InfoLevel,
			eventCfg:  nil,
			emitLevel: zerolog.DebugLevel,
			wantEmpty: true,
		},
		{
			name:      "level override widens to debug",
			baseLevel: zerolog.InfoLevel,
			eventCfg:  &EventLoggingConfig{LogLevel: "debug"},
			emitLevel: zerolog.DebugLevel,
			wantEmpty: false,
		},
		{
			name:      "level override restricts to error",
			baseLevel: zerolog.DebugLevel,
			eventCfg:  &EventLoggingConfig{LogLevel: "error"},
			emitLevel: zerolog.InfoLevel,
			wantEmpty: true,
		},
		{
			name:      "enabled false suppresses all",
			baseLevel: zerolog.InfoLevel,
			eventCfg:  &EventLoggingConfig{Enabled: boolPtr(false)},
			emitLevel: zerolog.ErrorLevel,
			wantEmpty: true,
		},
		{
			name:      "enabled true no suppression",
			baseLevel: zerolog.InfoLevel,
			eventCfg:  &EventLoggingConfig{Enabled: boolPtr(true)},
			emitLevel: zerolog.InfoLevel,
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logCtx := LoggerContext{
				Logger: zerolog.New(&buf).With().Timestamp().Logger().Level(tt.baseLevel),
				Writer: &buf,
			}
			logger, err := EventLogger(logCtx, "evt", tt.eventCfg)
			require.NoError(t, err)
			logger.WithLevel(tt.emitLevel).Msg("test msg")

			if tt.wantEmpty {
				assert.Empty(t, buf.String())
			} else {
				assert.Contains(t, buf.String(), "test msg")
			}
		})
	}
}

func TestEventLogger_FormatOverride_JSONToText(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	logger, err := EventLogger(logCtx, "text_event", &EventLoggingConfig{
		LogFormat: "text",
	})
	require.NoError(t, err)
	logger.Info().Msg("text output")

	output := buf.String()
	require.NotEmpty(t, output)
	assert.False(t, json.Valid([]byte(output)),
		"output should NOT be valid JSON when format overridden to text; got: %s", output)
	assert.Contains(t, output, "text output")
}

func TestEventLogger_FormatOverride_TextToJSON(t *testing.T) {
	var rawBuf bytes.Buffer
	textWriter := zerolog.ConsoleWriter{Out: &rawBuf, NoColor: true}
	logCtx := LoggerContext{
		Logger: zerolog.New(textWriter).With().Timestamp().Logger().Level(zerolog.InfoLevel),
		Writer: &rawBuf,
	}

	logger, err := EventLogger(logCtx, "json_event", &EventLoggingConfig{
		LogFormat: "json",
	})
	require.NoError(t, err)
	logger.Info().Msg("json output")

	output := rawBuf.String()
	require.NotEmpty(t, output)
	assert.True(t, json.Valid([]byte(output)),
		"output should be valid JSON when format overridden to json; got: %s", output)
}

func TestEventLogger_FormatAndLevel_Combined(t *testing.T) {
	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)

	logger, err := EventLogger(logCtx, "combo", &EventLoggingConfig{
		LogFormat: "text",
		LogLevel:  "debug",
	})
	require.NoError(t, err)

	logger.Debug().Msg("combo debug")
	output := buf.String()

	require.NotEmpty(t, output)
	assert.Contains(t, output, "combo debug")
	assert.False(t, json.Valid([]byte(output)),
		"should be text format, not JSON; got: %s", output)
}

func TestDeriveLoggerContext(t *testing.T) {
	t.Run("child level override applies", func(t *testing.T) {
		var buf bytes.Buffer
		parent := LoggerContext{
			Logger: zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.InfoLevel),
			Writer: &buf,
		}
		child, err := deriveLoggerContext(parent, &ObservabilityConfig{LogLevel: "debug"})
		require.NoError(t, err)

		child.Logger.Debug().Msg("child debug")
		assert.Contains(t, buf.String(), "child debug",
			"child log_level=debug should widen the parent's info level")
	})

	t.Run("child format override applies", func(t *testing.T) {
		var buf bytes.Buffer
		parent := LoggerContext{
			Logger: zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.InfoLevel),
			Writer: &buf,
		}
		child, err := deriveLoggerContext(parent, &ObservabilityConfig{LogFormat: "text"})
		require.NoError(t, err)

		child.Logger.Info().Msg("text child")
		output := buf.String()
		require.NotEmpty(t, output)
		assert.False(t, json.Valid([]byte(output)),
			"child log_format=text should override parent JSON; got: %s", output)
	})

	t.Run("no overrides returns parent as-is", func(t *testing.T) {
		var buf bytes.Buffer
		parent := LoggerContext{
			Logger: zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.WarnLevel),
			Writer: &buf,
		}
		child, err := deriveLoggerContext(parent, &ObservabilityConfig{})
		require.NoError(t, err)

		child.Logger.Info().Msg("should not appear")
		assert.Empty(t, buf.String(), "child with no overrides should inherit parent warn level")
	})

	t.Run("shares parent raw sink", func(t *testing.T) {
		var buf bytes.Buffer
		parent := LoggerContext{
			Logger: zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.InfoLevel),
			Writer: &buf,
		}
		child, err := deriveLoggerContext(parent, &ObservabilityConfig{LogLevel: "debug"})
		require.NoError(t, err)

		assert.Equal(t, parent.Writer, child.Writer,
			"child must share the parent's raw sink")
	})
}

func TestNewLoggerContext_InvalidLogLevel_ReturnsError(t *testing.T) {
	_, err := NewLoggerContext(&ObservabilityConfig{LogLevel: "verbose"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log_level")
}

func TestNewLoggerContext_InvalidLogFormat_ReturnsError(t *testing.T) {
	_, err := NewLoggerContext(&ObservabilityConfig{LogFormat: "xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log_format")
}

func TestEventLogger_InvalidLogLevel_ReturnsError(t *testing.T) {
	logCtx := jsonLogCtx(&bytes.Buffer{})
	_, err := EventLogger(logCtx, "test", &EventLoggingConfig{LogLevel: "verbose"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log_level")
}

func TestEventLogger_InvalidLogFormat_ReturnsError(t *testing.T) {
	logCtx := jsonLogCtx(&bytes.Buffer{})
	_, err := EventLogger(logCtx, "test", &EventLoggingConfig{LogFormat: "xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log_format")
}

func TestNewAuditObserverPrincipalClaimsAndCredentialEvents(t *testing.T) {
	emit := func(t *testing.T, cfg, top *ObservabilityConfig) string {
		t.Helper()
		var buf bytes.Buffer
		p := NewProvider(&Config{TrustDomain: "td.example", Observability: top})
		obs, err := p.newAuditObserver(cfg, LoggerContext{Logger: zerolog.New(&buf), Writer: &buf})
		require.NoError(t, err)
		_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "request-cfg"))
		probe.SubjectCredentialExtracted(&trust.MTLSCredential{Certificate: []byte("c")}, nil)
		probe.SubjectValidationSucceeded(&trust.Result{Subject: "s", Claims: map[string]any{"tenant": "t-1"}})
		probe.PolicyDecisionAllowWithoutIssue("allowed")
		probe.End()
		return buf.String()
	}
	configured := &ObservabilityConfig{
		Type:             "audit",
		PrincipalClaims:  map[string][]string{"tenant_id": {"tenant"}},
		CredentialEvents: &AuditCredentialEventsConfig{Subject: map[string]string{"mtls": "cert_seen"}},
	}

	t.Run("from the observer entry", func(t *testing.T) {
		out := emit(t, configured, nil)
		assert.Contains(t, out, `"attributes":{"tenant_id":"t-1"}`)
		assert.Contains(t, out, `"event":"parsec_cert_seen"`)
	})

	t.Run("from the top level", func(t *testing.T) {
		out := emit(t, &ObservabilityConfig{Type: "audit"}, configured)
		assert.Contains(t, out, `"attributes":{"tenant_id":"t-1"}`)
		assert.Contains(t, out, `"event":"parsec_cert_seen"`)
	})

	t.Run("none when unset", func(t *testing.T) {
		out := emit(t, &ObservabilityConfig{Type: "audit"}, nil)
		assert.NotContains(t, out, "attributes")
		assert.NotContains(t, out, "cert_seen")
	})
}

func TestNewAuditObserverRejectsInvalidPrincipalClaimsAndCredentialEvents(t *testing.T) {
	tests := []struct {
		name string
		cfg  ObservabilityConfig
		want string
	}{
		{"bad attribute name", ObservabilityConfig{PrincipalClaims: map[string][]string{"bad name": {"c"}}}, "invalid audit_principal_claims attribute"},
		{"attribute without claims", ObservabilityConfig{PrincipalClaims: map[string][]string{"tenant": {}}}, "lists no claims"},
		{"unknown credential type", ObservabilityConfig{CredentialEvents: &AuditCredentialEventsConfig{Actor: map[string]string{"api_key": "x"}}}, "unknown credential type"},
		{"bad event name", ObservabilityConfig{CredentialEvents: &AuditCredentialEventsConfig{Subject: map[string]string{"mtls": "bad event"}}}, "invalid event name"},
		{"reserved event name", ObservabilityConfig{CredentialEvents: &AuditCredentialEventsConfig{Subject: map[string]string{"mtls": "request"}}}, "invalid event name"},
		{"empty event name", ObservabilityConfig{CredentialEvents: &AuditCredentialEventsConfig{Subject: map[string]string{"mtls": ""}}}, "invalid event name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Type = "audit"
			p := providerWithObs(t, &tt.cfg)
			_, err := p.Observer()
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestLoaderReadsAuditPrincipalClaimsAndCredentialEvents(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "parsec.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`
observability:
  type: audit
  audit_principal_claims:
    org_id: ["org_id", "organization.id"]
  audit_credential_events:
    subject:
      mtls: cert_seen
    actor:
      header: key_seen
`), 0o600))
	loader, err := NewLoader(configPath)
	require.NoError(t, err)
	cfg, err := loader.Get()
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"org_id": {"org_id", "organization.id"}}, cfg.Observability.PrincipalClaims)
	require.NotNil(t, cfg.Observability.CredentialEvents)
	assert.Equal(t, map[string]string{"mtls": "cert_seen"}, cfg.Observability.CredentialEvents.Subject)
	assert.Equal(t, map[string]string{"header": "key_seen"}, cfg.Observability.CredentialEvents.Actor)
}

// TestShippedConfigKeepsDeploymentAuditOutput checks that the deployment
// names core no longer knows about are reproduced by configs/parsec.yaml.
func TestShippedConfigKeepsDeploymentAuditOutput(t *testing.T) {
	loader, err := NewLoader("../../configs/parsec.yaml")
	require.NoError(t, err)
	cfg, err := loader.Get()
	require.NoError(t, err)

	var buf bytes.Buffer
	logCtx := jsonLogCtx(&buf)
	p := NewProvider(cfg)
	p.logCtx = &logCtx
	obs, err := p.Observer()
	require.NoError(t, err)

	_, probe := obs.AuthzCheckStarted(request.WithID(context.Background(), "shipped-config"))
	probe.SubjectCredentialExtracted(&trust.MTLSCredential{Certificate: []byte("c")}, nil)
	probe.SubjectValidationSucceeded(&trust.Result{Subject: "s", Claims: map[string]any{
		"organization": map[string]any{"id": "org-1"}, "account_number": "acct-1",
	}})
	probe.ActorCredentialExtracted(&trust.HeaderCredential{Headers: map[string]string{"x-key": "k"}}, nil)
	probe.PolicyDecisionAllowWithoutIssue("allowed")
	probe.End()

	events := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record["schema_version"] != nil {
			events[record["event"].(string)] = record
		}
	}
	require.Contains(t, events, "parsec_validate_ssl_cert")
	require.Contains(t, events, "parsec_verify_psk")
	subject := events["parsec_request"]["subject"].(map[string]any)
	assert.Equal(t, map[string]any{"org_id": "org-1", "account_number": "acct-1"}, subject["attributes"])
}
