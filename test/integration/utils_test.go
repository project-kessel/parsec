package integration

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// waitForServer polls the given port until a TCP connection succeeds or timeout is reached.
// This provides a deterministic way to wait for server startup without arbitrary sleeps.
func waitForServer(t *testing.T, port int, timeout time.Duration) {
	t.Helper()

	addr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		// Brief sleep between attempts to avoid tight loop
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("server on port %d did not become ready within %v", port, timeout)
}
