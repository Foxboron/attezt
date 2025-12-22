package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func Encode[T any](w http.ResponseWriter, status int, v T) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
	return nil
}

func Decode[T any](b io.ReadCloser) (T, error) {
	var v T
	var buf bytes.Buffer
	tee := io.TeeReader(b, &buf)
	if err := json.NewDecoder(tee).Decode(&v); err != nil {
		return v, fmt.Errorf("decode json: %w", err)
	}
	fmt.Println(buf.String())
	return v, nil
}
