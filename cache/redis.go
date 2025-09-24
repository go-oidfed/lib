package cache

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/vmihailenco/msgpack/v5"
)

type redisCache struct {
	client *redis.Client
	ctx    context.Context
}

// Get implements the Cache interface
func (c redisCache) Get(key string, target any) (bool, error) {
	val, err := c.client.Get(c.ctx, key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return false, errors.Wrap(err, "error while obtaining from cache")
		}
		return false, nil
	}
	return true, msgpack.Unmarshal([]byte(val), target)
}

// Set implements the Cache interface
func (c redisCache) Set(key string, value any, expiration time.Duration) error {
	data, err := msgpack.Marshal(value)
	if err != nil {
		return err
	}
	return c.client.Set(c.ctx, key, data, expiration).Err()
}

// Delete implements the Cache interface
func (c redisCache) Delete(key string) error {
	return c.client.Unlink(c.ctx, key).Err()
}

// Clear implements the Cache interface
func (c redisCache) Clear(prefix string) error {
	const batchSize = 500
	pattern := prefix + "*"
	iter := c.client.Scan(context.Background(), 0, pattern, 0).Iterator()
	keys := make([]string, 0, batchSize)

	for iter.Next(context.Background()) {
		keys = append(keys, iter.Val())
		if len(keys) >= batchSize {
			if err := c.client.Unlink(context.Background(), keys...).Err(); err != nil {
				return err
			}
			keys = keys[:0]
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := c.client.Unlink(context.Background(), keys...).Err(); err != nil {
			return err
		}
	}
	return nil
}

// UseRedisCache creates a new redis cache with the passed options and sets it to be used
func UseRedisCache(options *redis.Options) error {
	rdb := redis.NewClient(options)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return errors.Wrap(err, "could not connect to redis cache")
	}
	SetCache(
		redisCache{
			client: rdb,
			ctx:    context.Background(),
		},
	)
	return nil
}
