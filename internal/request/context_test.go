package request

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestIDContext(t *testing.T) {
	ctx := WithID(context.Background(), "request-123")
	require.Equal(t, "request-123", ID(ctx))
	require.Empty(t, ID(context.Background()))
}
