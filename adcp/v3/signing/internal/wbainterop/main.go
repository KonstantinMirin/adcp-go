// Command wbainterop is the adcp-go adapter for the Web Bot Auth interop
// harness in the AdCP spec repository (tests/wba-interop/). The harness
// grades this SDK against Cloudflare's web-bot-auth reference in both
// directions: the SDK signs and the reference verifies, and the reference
// signs and the SDK verifies.
//
// The adapter reads one JSON operation on standard input and writes one JSON
// result on standard output. It calls only the signing package's public API:
//
//	sign_request      {key, origin, request, now}             -> the signed request
//	sign_directory    {keys, origin, now}                     -> {url, status, headers, body}
//	verify_request    {request, directories, now, prior}      -> {ok, identity, keyid}
//	verify_directory  {origin, response, now}                 -> {ok, keyids}
//
// key and keys are private JWKs. A request is {method, url, headers, body}
// and a response is {url, status, headers, body}, with headers as a map of
// lowercase field names. directories maps an origin to its signed directory
// response. now is a Unix time in seconds and is the only clock the SDK reads.
// The adapter verifies each request in prior with the same replay store
// before the graded request, so the harness builds replay state without
// knowing how the SDK stores it. A failure is {ok: false, status, rule,
// error}: status is the HTTP status the SDK assigns (0 when it assigns none),
// and rule is "discovery" for a key discovery failure, the AdCP error code for
// an authorization failure, and "signature" for any other signature failure.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/adcontextprotocol/adcp-go/adcp/v3/signing"
)

type message struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type operation struct {
	Op          string             `json:"op"`
	Request     message            `json:"request"`
	Response    message            `json:"response"`
	Directories map[string]message `json:"directories"`
	Origin      string             `json:"origin"`
	Now         int64              `json:"now"`
	Key         json.RawMessage    `json:"key"`
	Keys        []json.RawMessage  `json:"keys"`
	Prior       []message          `json:"prior"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		write(failure(0, "adapter", err))
		return
	}
	var op operation
	if err := json.Unmarshal(raw, &op); err != nil {
		write(failure(0, "adapter", err))
		return
	}
	write(run(op))
}

func write(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }

func run(op operation) any {
	switch op.Op {
	case "sign_request":
		return signRequest(op)
	case "sign_directory":
		return signDirectory(op)
	case "verify_request":
		return verifyRequest(op)
	case "verify_directory":
		return verifyDirectory(op)
	default:
		return failure(0, "adapter", fmt.Errorf("unknown operation %q", op.Op))
	}
}

func failure(status int, rule string, err error) map[string]any {
	return map[string]any{"ok": false, "status": status, "rule": rule, "error": err.Error()}
}

// sdkFailure reports err with the status and reason the SDK assigned.
func sdkFailure(err error) map[string]any {
	we := signing.AsWBAError(err)
	switch {
	case we == nil:
		return failure(0, "error", err)
	case we.DiscoveryFailure:
		return failure(we.Status, "discovery", err)
	case we.Code != "":
		return failure(we.Status, we.Code, err)
	default:
		return failure(we.Status, "signature", err)
	}
}

func clock(now int64) func() time.Time { return func() time.Time { return time.Unix(now, 0) } }

// privateKey decodes a private JWK into the crypto key the SDK signs with.
func privateKey(raw json.RawMessage) (any, error) {
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	if k.IsPublic() {
		return nil, errors.New("key is not a private JWK")
	}
	return k.Key, nil
}

func header(fields map[string]string) http.Header {
	h := http.Header{}
	for name, value := range fields {
		h.Set(name, value)
	}
	return h
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		out[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return out
}

func directoryURL(origin string) string {
	return strings.TrimSuffix(origin, "/") + signing.DirectoryPath
}

func signRequest(op operation) any {
	key, err := privateKey(op.Key)
	if err != nil {
		return failure(0, "key", err)
	}
	var body io.Reader
	if op.Request.Body != "" {
		body = strings.NewReader(op.Request.Body)
	}
	req, err := http.NewRequest(op.Request.Method, op.Request.URL, body)
	if err != nil {
		return failure(0, "request", err)
	}
	req.Header = header(op.Request.Headers)
	if err := signing.SignWebBotAuthRequest(req, key, signing.WBASignOptions{AgentOrigin: op.Origin, Clock: clock(op.Now)}); err != nil {
		return sdkFailure(err)
	}
	return message{Method: op.Request.Method, URL: op.Request.URL, Headers: flatten(req.Header), Body: op.Request.Body}
}

func signDirectory(op operation) any {
	keys := make([]any, 0, len(op.Keys))
	for _, raw := range op.Keys {
		key, err := privateKey(raw)
		if err != nil {
			return failure(0, "key", err)
		}
		keys = append(keys, key)
	}
	// created is backdated by a minute, as the reference signer's is, so a
	// verifier that allows no skew on directory signatures accepts it.
	d, err := signing.SignKeyDirectory(op.Origin, keys, time.Unix(op.Now-60, 0), 24*time.Hour)
	if err != nil {
		return sdkFailure(err)
	}
	return message{URL: directoryURL(op.Origin), Status: d.Status, Headers: flatten(d.Header), Body: string(d.Body)}
}

func verifyRequest(op operation) any {
	fetch := func(_ context.Context, url string) (*signing.DirectoryResponse, error) {
		for origin, d := range op.Directories {
			if directoryURL(origin) == url {
				return &signing.DirectoryResponse{Status: d.Status, Header: header(d.Headers), Body: []byte(d.Body)}, nil
			}
		}
		return nil, fmt.Errorf("no directory at %s", url)
	}
	opts := signing.WBAVerifyOptions{
		Keys:   signing.NewDirectoryResolver(signing.DirectoryResolverOptions{Fetch: fetch, Clock: clock(op.Now)}),
		Replay: signing.NewMemoryReplayStore(0),
		Clock:  clock(op.Now),
	}
	var (
		signer *signing.VerifiedSigner
		err    error
	)
	for _, m := range append(op.Prior, op.Request) {
		req, rerr := http.NewRequest(m.Method, m.URL, bytes.NewBufferString(m.Body))
		if rerr != nil {
			return failure(http.StatusBadRequest, "request", rerr)
		}
		req.Header = header(m.Headers)
		req.Host = req.URL.Host
		signer, err = signing.VerifyWebBotAuthRequest(req, opts)
	}
	if err != nil {
		return sdkFailure(err)
	}
	return map[string]any{"ok": true, "identity": signer.AgentURL, "keyid": signer.KeyID}
}

func verifyDirectory(op operation) any {
	keys, err := signing.VerifyDirectoryResponse(op.Origin, &signing.DirectoryResponse{
		Status: op.Response.Status, Header: header(op.Response.Headers), Body: []byte(op.Response.Body),
	}, time.Unix(op.Now, 0))
	if err != nil {
		return sdkFailure(err)
	}
	ids := make([]string, 0, len(keys))
	for kid := range keys {
		ids = append(ids, kid)
	}
	return map[string]any{"ok": true, "keyids": ids}
}
