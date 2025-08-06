// redis.go
package main

import (
	"context"
	"log"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

var RedisClient *redis.Client
var ctx = context.Background()

func InitRedis() {
	viper.AutomaticEnv() // Read environment variables automatically
	url := viper.GetString("REDIS_URL")
	opt, err := redis.ParseURL(url)
	if err != nil {
		log.Fatalf("Invalid REDIS_URL: %v", err)
	}

	RedisClient = redis.NewClient(opt)
	RedisClient = redis.NewClient(opt)

	_, err = RedisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("could not connect to Redis: %v", err)
	}

	log.Println("✅ connected to Redis")
}
