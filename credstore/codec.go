package credstore

import (
	"encoding/json"
	"fmt"
)

// Codec handles encoding/decoding values to/from strings for storage.
type Codec[T any] interface {
	Encode(v T) (string, error)
	Decode(s string) (T, error)
}

// JSONCodec encodes T as JSON.
type JSONCodec[T any] struct{}

// Encode marshals v to a JSON string.
func (JSONCodec[T]) Encode(v T) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}
	return string(data), nil
}

// Decode unmarshals a JSON string into T.
func (JSONCodec[T]) Decode(s string) (T, error) {
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return v, fmt.Errorf("failed to unmarshal data: %w", err)
	}
	return v, nil
}

// StringCodec is the identity codec for plain strings.
type StringCodec struct{}

// Encode returns the string as-is.
func (StringCodec) Encode(v string) (string, error) {
	return v, nil
}

// Decode returns the string as-is.
func (StringCodec) Decode(s string) (string, error) {
	return s, nil
}
