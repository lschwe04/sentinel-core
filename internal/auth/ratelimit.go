// sentinel-core: internal/auth/ratelimit.go (Neu)
package auth

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

var (
	limiters = make(map[string]*rate.Limiter)
	mu       sync.Mutex
)

// getTenantLimiter weist jedem Systemhaus ein dediziertes Limit zu
func getTenantLimiter(tenantID string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()
	limiter, exists := limiters[tenantID]
	if !exists {
		// Limit: 50 Requests/Sekunde pro Systemhaus
		limiter = rate.NewLimiter(50, 100)
		limiters[tenantID] = limiter
	}
	return limiter
}

func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID != "" {
			if !getTenantLimiter(tenantID).Allow() {
				http.Error(w, `{"error": "Rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
