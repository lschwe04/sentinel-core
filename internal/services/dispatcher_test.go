// sentinel-core: internal/services/dispatcher_test.go
package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDispatchAlert_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewHTTPDispatcher()
	err := dispatcher.DispatchAlert(context.Background(), "tenant-alpha", "Test Alert Message", server.URL)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestDispatchAlert_RetryAndFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dispatcher := NewHTTPDispatcher()
	dispatcher.MaxRetries = 2
	// Verkürzte Backoffs für den Test sind im echten Dispatcher integriert, hier greift die Zählung

	err := dispatcher.DispatchAlert(context.Background(), "tenant-beta", "Fail Alert", server.URL)
	if err == nil {
		t.Fatal("expected error after max retries, got nil")
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}
