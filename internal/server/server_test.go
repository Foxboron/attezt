package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/foxboron/attezt/internal/attest"
)

type deniedInventory struct{ lookups int }

func (d *deniedInventory) Lookup(*attest.Attestation) (bool, error) { d.lookups++; return false, nil }
func (*deniedInventory) GetEntry(string) (any, error)               { return nil, nil }
func (*deniedInventory) Init(map[string]any) error                  { return nil }
func (*deniedInventory) Enroll(map[string]any) error                { return nil }
func (*deniedInventory) Remove(map[string]any) error                { return nil }
func (*deniedInventory) List() (any, error)                         { return nil, nil }

func TestActivationExpiresAndIsConsumed(t *testing.T) {
	for _, expired := range []bool{false, true} {
		db := &deniedInventory{}
		s := NewTPMAttestServer(nil, nil, db)
		secret := bytes.Repeat([]byte{1}, 32)
		expires := time.Now().Add(time.Minute)
		if expired {
			expires = time.Now().Add(-time.Minute)
		}
		s.state[string(secret)] = activation{params: &attest.Attestation{}, expires: expires}
		body, err := json.Marshal(attest.SecretRequest{Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			w := httptest.NewRecorder()
			s.Handlers().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/secret", bytes.NewReader(body)))
			if w.Code != http.StatusForbidden {
				t.Fatalf("unexpected response: %d", w.Code)
			}
		}
		if len(s.state) != 0 {
			t.Fatal("activation was not consumed")
		}
		want := 1
		if expired {
			want = 0
		}
		if db.lookups != want {
			t.Fatalf("inventory checked %d times, want %d", db.lookups, want)
		}
	}
}

func TestRejectsMalformedAndWrongMethod(t *testing.T) {
	s := NewTPMAttestServer(nil, nil, &deniedInventory{})
	for _, path := range []string{"/attest", "/secret"} {
		w := httptest.NewRecorder()
		s.Handlers().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
		for _, input := range []string{"null", "{}", "broken"} {
			w = httptest.NewRecorder()
			s.Handlers().ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(input)))
			if w.Code < 400 {
				t.Fatalf("accepted %s on %s: %d", input, path, w.Code)
			}
		}
	}
}

func TestConcurrentActivationIsConsumedOnce(t *testing.T) {
	db := &deniedInventory{}
	s := NewTPMAttestServer(nil, nil, db)
	secret := bytes.Repeat([]byte{1}, 32)
	s.state[string(secret)] = activation{params: &attest.Attestation{}, expires: time.Now().Add(time.Minute)}
	body, err := json.Marshal(attest.SecretRequest{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			s.Handlers().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/secret", bytes.NewReader(body)))
			if w.Code != http.StatusForbidden {
				t.Errorf("unexpected status %d", w.Code)
			}
		})
	}
	wg.Wait()
	if db.lookups != 1 {
		t.Fatalf("activation reached inventory %d times", db.lookups)
	}
}
