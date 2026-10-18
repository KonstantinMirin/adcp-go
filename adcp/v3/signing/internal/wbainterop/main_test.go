package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// TestAdapterRoundTrip runs the four operations against each other: the
// adapter's own signed directory and request verify, and replaying the
// request through prior is refused with 429.
func TestAdapterRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := json.Marshal(jose.JSONWebKey{Key: priv})
	require.NoError(t, err)
	const origin = "https://buyer.example.com"
	now := time.Now().Unix()

	dir, ok := run(operation{Op: "sign_directory", Keys: []json.RawMessage{key}, Origin: origin, Now: now}).(message)
	require.True(t, ok)
	got := run(operation{Op: "verify_directory", Origin: origin, Response: dir, Now: now}).(map[string]any)
	require.Equal(t, true, got["ok"], got)
	keyids := got["keyids"].([]string)
	require.Len(t, keyids, 1)

	signed, ok := run(operation{Op: "sign_request", Key: key, Origin: origin, Now: now, Request: message{
		Method: http.MethodPost, URL: "https://seller.example.com/mcp/",
		Headers: map[string]string{"content-type": "application/json"}, Body: `{"jsonrpc":"2.0","id":1}`,
	}}).(message)
	require.True(t, ok)
	verify := operation{Op: "verify_request", Request: signed, Directories: map[string]message{origin: dir}, Now: now}
	got = run(verify).(map[string]any)
	require.Equal(t, true, got["ok"], got)
	require.Equal(t, origin, got["identity"])
	require.Equal(t, keyids[0], got["keyid"])

	verify.Prior = []message{signed}
	got = run(verify).(map[string]any)
	require.Equal(t, false, got["ok"])
	require.Equal(t, http.StatusTooManyRequests, got["status"])

	got = run(operation{Op: "unknown"}).(map[string]any)
	require.Equal(t, false, got["ok"])
}
