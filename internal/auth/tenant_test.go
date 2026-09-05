package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestTenantAuthMiddlewareRejectsInvalidToken(t *testing.T) {
	oldSecret := os.Getenv("JWT_SECRET")
	t.Setenv("JWT_SECRET", "01234567890123456789012345678901")
	t.Cleanup(func() { _ = os.Setenv("JWT_SECRET", oldSecret) })

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := TenantAuthMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestTenantAuthMiddlewareBindsTenantClaim(t *testing.T) {
	secret := "01234567890123456789012345678901"
	t.Setenv("JWT_SECRET", secret)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "tenant-1",
		"exp":       time.Now().Add(time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Context().Value(TenantKey); got != "tenant-1" {
			t.Fatalf("expected tenant-1 in context, got %v", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := TenantAuthMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tenant-ID", "tenant-2")
	req.Header.Set("Authorization", "Bearer "+signed)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tenant mismatch, got %d", res.Code)
	}

	req.Header.Set("X-Tenant-ID", "tenant-1")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for valid token, got %d", res.Code)
	}
}
