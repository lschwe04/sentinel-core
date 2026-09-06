package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type ValidationCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewValidationCache(client *redis.Client, ttl time.Duration) *ValidationCache {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &ValidationCache{client: client, ttl: ttl}
}

func (c *ValidationCache) Get(ctx context.Context, tokenDigest string) (bool, error) {
	if c == nil || c.client == nil {
		return false, redis.Nil
	}
	value, err := c.client.Get(ctx, "sentinel:token-valid:"+tokenDigest).Result()
	return value == "1", err
}

func (c *ValidationCache) Put(ctx context.Context, tokenDigest string, valid bool) error {
	if c == nil || c.client == nil {
		return redis.Nil
	}
	value := "0"
	if valid {
		value = "1"
	}
	return c.client.Set(ctx, "sentinel:token-valid:"+tokenDigest, value, c.ttl).Err()
}
