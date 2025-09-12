package main

import (
	"asterfusion/client/logger"
	"fmt"

	"github.com/go-redis/redis"
)

type RedisSingleObj struct {
	Redis_host string
	Redis_port uint16
	Redis_auth string
	Database   int
	Db         *redis.Client
}

func (r *RedisSingleObj) InitSingleRedis() (err error) {
	redisAddr := fmt.Sprintf("%s:%d", r.Redis_host, r.Redis_port)
	r.Db = redis.NewClient(&redis.Options{
		Addr:        redisAddr,
		Password:    r.Redis_auth,
		DB:          r.Database,
		IdleTimeout: 300,
		PoolSize:    100,
	})
	logger.Info("Connecting to Redis server at address %s", redisAddr)

	_, err = r.Db.Ping().Result()
	if err != nil {
		logger.Error("Failed to connect to Redis server: %s", err.Error())
		return err
	} else {
		logger.Info("Successfully connected to Redis server.")
		return nil
	}
}

func ConnectToRedis(dbtype DBType) (*RedisSingleObj, error) {
	conn := &RedisSingleObj{
		Redis_host: "127.0.0.1",
		Redis_port: 6379,
		Database:   int(dbtype),
	}

	err := conn.InitSingleRedis()
	if err != nil {
		logger.Error("Failed to connect to Redis server: %s", err.Error())
		return nil, err
	}
	return conn, nil
}

func CloseDbConn(conn RedisSingleObj) {
	conn.Db.Close()
}
