package httpclient

import "context"

// HTTPClientObserver observes outbound HTTP client requests made via the
// [Registry]. Implementations should embed [NoOpHTTPClientObserver] for
// forward compatibility with new methods added to this interface.
type HTTPClientObserver interface {
	// RequestStarted is called when an outbound HTTP request begins.
	// clientName is the [ClientName] from the registry (empty for inline clients).
	// Returns a potentially modified context and a probe to track the request.
	RequestStarted(ctx context.Context, clientName string, method string, host string) (context.Context, RequestProbe)
}

// RequestProbe tracks a single outbound HTTP request.
// Implementations should embed [NoOpRequestProbe] for forward compatibility.
type RequestProbe interface {
	// StatusCode records the HTTP response status code.
	StatusCode(code int)

	// Error records a transport-level error (timeout, connection refused, etc.).
	Error(err error)

	// ConnectionReused records whether the underlying TCP connection was
	// reused (true) or newly established (false). Called from an
	// httptrace.ClientTrace.GotConn callback during the round-trip.
	ConnectionReused(reused bool)

	// ProtocolVersion records the negotiated HTTP protocol version
	// (e.g. "HTTP/1.1", "HTTP/2.0") from the response. Only called on
	// successful round-trips; omitted on transport-level errors.
	ProtocolVersion(proto string)

	// TLSCurve records the negotiated TLS key exchange group
	// (e.g. "X25519MLKEM768", "X25519", "CurveP256"). Only called on
	// successful round-trips over TLS where a group was negotiated;
	// omitted for plaintext HTTP and transport-level errors.
	TLSCurve(curve string)

	// End signals the request is complete (for timing). Called via defer.
	End()
}

// NoOpHTTPClientObserver is a no-op implementation for forward compatibility
// and testing.
type NoOpHTTPClientObserver struct{}

// RequestStarted returns the context unchanged and a no-op probe.
func (NoOpHTTPClientObserver) RequestStarted(ctx context.Context, _ string, _ string, _ string) (context.Context, RequestProbe) {
	return ctx, NoOpRequestProbe{}
}

// NoOpRequestProbe is a no-op implementation for forward compatibility.
type NoOpRequestProbe struct{}

func (NoOpRequestProbe) StatusCode(int)         {}
func (NoOpRequestProbe) Error(error)            {}
func (NoOpRequestProbe) ConnectionReused(bool)  {}
func (NoOpRequestProbe) ProtocolVersion(string) {}
func (NoOpRequestProbe) TLSCurve(string)        {}
func (NoOpRequestProbe) End()                   {}
