# Server Implementation

This is where the API interfaces are handled.

## Form Marshaler for RFC 8693 Compliance

### Overview

The token exchange endpoint must support `application/x-www-form-urlencoded` per [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html). Since grpc-gateway defaults to JSON, we implement a custom marshaler.

### Implementation: `form_marshaler.go`

The `FormMarshaler` implements grpc-gateway's `runtime.Marshaler` interface to handle form-encoded requests.

#### Key Design Decisions

1. **Request Decoding**: Form-encoded → Map → JSON → Proto
   - Parse form data using `url.ParseQuery`
   - Convert to flat map
   - Marshal to JSON as intermediate format
   - Use protojson to unmarshal into proto message
   
   **Why?** Proto unmarshaling expects structured data. Going through JSON avoids reimplementing proto field mapping.

2. **Response Encoding**: Always JSON
   - OAuth 2.0 responses are JSON by spec
   - Clients expect `Content-Type: application/json` in responses
   - Even form-encoded requests get JSON responses

3. **Dual Content-Type Support**
   - Form-encoded: RFC 8693 OAuth clients
   - JSON: gRPC-style clients, testing tools
   - Registered via `runtime.WithMarshalerOption`

#### Known Limitations

1. **Nested Fields**: Form encoding is flat; nested proto messages won't work correctly
   - Not an issue for RFC 8693 (all fields are flat strings)
   
2. **Array Fields**: Form encoding can have repeated keys, but our implementation uses `url.Values` which handles this
   - Currently takes the first value if multiple present
   
3. **Type Conversion**: All form values are strings
   - For `ExchangeRequest`, this is correct (per RFC 8693)
   - Numeric fields like `expires_in` in responses are handled by JSON marshaler

### Testing

```bash
# Run unit tests
go test -v ./internal/server/

# Run integration tests
go test -v ./test/integration/
```

### Example Usage

**Form-encoded request (RFC 8693):**
```bash
curl -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=eyJhbGciOiJIUzI1NiJ9..." \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=https://api.example.com"
```

**JSON request (also supported):**
```bash
curl -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "eyJhbGciOiJIUzI1NiJ9...",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "https://api.example.com"
  }'
```

Both produce the same JSON response:
```json
{
  "access_token": "...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
  "token_type": "Bearer",
  "expires_in": 300
}
```

### References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [grpc-gateway Issue #7 - Form encoding support](https://github.com/grpc-ecosystem/grpc-gateway/issues/7)
- [grpc-gateway Custom Marshalers](https://github.com/grpc-ecosystem/grpc-gateway#customizing-the-gateway)

### Future Improvements

1. **Performance**: Consider caching the JSON intermediate step
2. **Validation**: Add RFC 8693 field validation (required vs optional)
3. **Error Messages**: Improve error messages for malformed form data
4. **Streaming**: Currently doesn't support streaming (not needed for token exchange)

