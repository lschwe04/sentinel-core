package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisRateLimitScript = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return current
`

// RedisRateLimiter implements a fixed-window limit shared by all Hub replicas.
// The key must contain an authenticated tenant identity, not an arbitrary header.
type RedisRateLimiter struct {
	client *redis.Client
	limit  int64
	window time.Duration
}

func NewRedisRateLimiter(client *redis.Client, limit int64, window time.Duration) *RedisRateLimiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Second
	}
	return &RedisRateLimiter{client: client, limit: limit, window: window}
}

func (limiter *RedisRateLimiter) Allow(ctx context.Context, tenantID string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false, nil
	}
	windowID := time.Now().UTC().UnixMilli() / limiter.window.Milliseconds()
	key := "sentinel:ratelimit:" + tenantID + ":" + strconv.FormatInt(windowID, 10)
	count, err := limiter.client.Eval(ctx, redisRateLimitScript, []string{key}, limiter.window.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return count <= limiter.limit, nil
}

// RedisRateLimitMiddleware must be mounted after authentication middleware.
func RedisRateLimitMiddleware(limiter *RedisRateLimiter, failClosed bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, _ := r.Context().Value(AuthenticatedTenantKey).(string)
		allowed, err := limiter.Allow(r.Context(), tenantID)
		if err != nil {
			if failClosed {
				http.Error(w, `{"error":"rate limiter unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(limiter.window/time.Second), 10))
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
