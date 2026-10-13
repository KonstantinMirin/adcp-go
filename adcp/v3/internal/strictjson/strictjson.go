// Package strictjson validates JSON documents that carry authority: trust
// records, key directories, and revocation lists. Go's encoding/json keeps
// the last of two duplicate object keys, and another parser may keep the
// first, so a document with duplicate keys could mean different things to
// different readers. Validate rejects it before any field is read.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DefaultMaxDepth is the nesting limit AdCP applies to trust records
// (security.mdx, Web Bot Auth identities: "nesting depth 32").
const DefaultMaxDepth = 32

// ErrInvalid is wrapped by every validation failure.
var ErrInvalid = errors.New("strictjson: invalid document")

// Validate reports whether data is exactly one JSON value with no duplicate
// object keys (compared after unescaping) and nesting no deeper than
// maxDepth. maxDepth <= 0 selects DefaultMaxDepth.
func Validate(data []byte, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if !json.Valid(data) {
		return fmt.Errorf("%w: not valid JSON", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object  bool
		keys    map[string]struct{}
		wantKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.wantKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", ErrInvalid)
			}
			if _, dup := top.keys[key]; dup {
				return fmt.Errorf("%w: duplicate object key", ErrInvalid)
			}
			top.keys[key] = struct{}{}
			top.wantKey = false
			continue
		}
		if top != nil && top.object {
			top.wantKey = true
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxDepth {
					return fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
				}
				stack = append(stack, &frame{object: d == '{', keys: map[string]struct{}{}, wantKey: d == '{'})
			case ']', '}':
				stack = stack[:len(stack)-1]
			}
		}
	}
	return nil
}

// Unmarshal validates data with Validate, then decodes it into v.
func Unmarshal(data []byte, maxDepth int, v any) error {
	if err := Validate(data, maxDepth); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}
