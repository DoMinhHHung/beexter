package redisclient

import (
	"context"
	"fmt"

	"github.com/DoMinhHHung/beexster/service/identity/internal/config"
	"github.com/redis/go-redis/v9"
)

func Open(
	ctx context.Context,
	cfg config.RedisConfig,
) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:        cfg.Addr,
		Username:    cfg.Username,
		Password:    cfg.Password,
		DB:          cfg.DB,
		DialTimeout: cfg.ConnectTimeout,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		closeErr := client.Close()
		if closeErr != nil {
			return nil, fmt.Errorf(
				"ping Redis: %w; close Redis client: %v",
				err,
				closeErr,
			)
		}

		return nil, fmt.Errorf("ping Redis: %w", err)
	}

	return client, nil
}
