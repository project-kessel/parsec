package otel

import (
	"context"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpclient"
)

type httpClientObserver struct {
	httpclient.NoOpHTTPClientObserver

	requestDuration metric.Float64Histogram
	clock           clock.Clock
}

func newHTTPClientObserver(m metric.Meter, clk clock.Clock) (*httpClientObserver, error) {
	rd, err := m.Float64Histogram("parsec.httpclient.request.duration",
		metric.WithDescription("Outbound HTTP client request duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	return &httpClientObserver{
		requestDuration: rd,
		clock:           clk,
	}, nil
}

func (o *httpClientObserver) RequestStarted(
	ctx context.Context,
	clientName string,
	method string,
	host string,
) (context.Context, httpclient.RequestProbe) {
	return ctx, &requestProbe{
		obs:             o,
		ctx:             ctx,
		startTime:       o.clock.Now(),
		status:          successStatusAttr,
		clientName:      attribute.String("client_name", clientName),
		method:          attribute.String("method", method),
		host:            attribute.String("host", host),
		statusCode:      attribute.String("status_code", ""),
		connection:      attribute.String("connection", ""),
		protocolVersion: attribute.String("network.protocol.version", ""),
		tlsCurve:        attribute.String("tls.curve", ""),
	}
}

type requestProbe struct {
	httpclient.NoOpRequestProbe
	obs             *httpClientObserver
	ctx             context.Context
	startTime       time.Time
	status          attribute.KeyValue
	clientName      attribute.KeyValue
	method          attribute.KeyValue
	host            attribute.KeyValue
	statusCode      attribute.KeyValue
	connection      attribute.KeyValue
	protocolVersion attribute.KeyValue
	tlsCurve        attribute.KeyValue
}

func (p *requestProbe) StatusCode(code int) {
	p.statusCode = attribute.String("status_code", strconv.Itoa(code))
}

func (p *requestProbe) Error(_ error) {
	p.status = errorStatusAttr
}

func (p *requestProbe) ConnectionReused(reused bool) {
	if reused {
		p.connection = attribute.String("connection", "reused")
	} else {
		p.connection = attribute.String("connection", "new")
	}
}

func (p *requestProbe) ProtocolVersion(proto string) {
	p.protocolVersion = attribute.String("network.protocol.version", proto)
}

func (p *requestProbe) TLSCurve(curve string) {
	p.tlsCurve = attribute.String("tls.curve", curve)
}

func (p *requestProbe) End() {
	keys := []attribute.KeyValue{p.clientName, p.method, p.host, p.status}
	if p.statusCode.Value.AsString() != "" {
		keys = append(keys, p.statusCode)
	}
	if p.connection.Value.AsString() != "" {
		keys = append(keys, p.connection)
	}
	if p.protocolVersion.Value.AsString() != "" {
		keys = append(keys, p.protocolVersion)
	}
	if p.tlsCurve.Value.AsString() != "" {
		keys = append(keys, p.tlsCurve)
	}
	attrs := metric.WithAttributeSet(attribute.NewSet(keys...))
	p.obs.requestDuration.Record(p.ctx, p.obs.clock.Since(p.startTime).Seconds(), attrs)
}

var (
	_ httpclient.HTTPClientObserver = (*httpClientObserver)(nil)
	_ httpclient.RequestProbe       = (*requestProbe)(nil)
)
