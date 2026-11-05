package json

import (
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestBodiesAreNotLogged(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()
	const marker = "activation-secret-must-not-be-logged"
	if _, err := Decode[map[string]string](io.NopCloser(strings.NewReader(`{"secret":"` + marker + `"}`))); err != nil {
		t.Fatal(err)
	}
	if err := Encode(httptest.NewRecorder(), 200, map[string]string{"secret": marker}); err != nil {
		t.Fatal(err)
	}
	_, err = Decode[map[string]string](io.NopCloser(strings.NewReader(`{"secret":"` + marker + `", broken}`)))
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("malformed request body exposed in error")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	logged, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(logged) != 0 {
		t.Fatal("request or response body written to stdout")
	}
}
