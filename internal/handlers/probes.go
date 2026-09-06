package handlers

import (
	"context"
	"net/http"
	"time"

	"sentinel-core/internal/db"

	"github.com/redis/go-redis/v9"
)

func HandleLiveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func HandleReadiness(redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if db.Pool == nil || db.Pool.Ping(ctx) != nil || redisClient == nil || redisClient.Ping(ctx).Err() != nil {
			http.Error(w, "dependencies unavailable\n", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	}
}
