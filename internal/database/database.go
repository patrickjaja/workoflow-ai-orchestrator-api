package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/workoflow/ai-orchestrator-api/internal/config"
	"github.com/workoflow/ai-orchestrator-api/internal/models"

	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database interface {
	DB() *gorm.DB
	Close() error
	Ping() error
	AutoMigrate() error
}

type database struct {
	db *gorm.DB
}

func Initialize(cfg config.DatabaseConfig) (Database, error) {
	// Create a custom logger that avoids the "insufficient arguments" error
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,   // Slow SQL threshold
			LogLevel:                  logger.Silent, // Log level
			IgnoreRecordNotFoundError: true,          // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,          // Disable color
		},
	)

	gormConfig := &gorm.Config{
		Logger:                                   newLogger,
		DisableForeignKeyConstraintWhenMigrating: false,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	db, err := gorm.Open(postgres.Open(cfg.URL), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxConnections)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConnections)
	sqlDB.SetConnMaxLifetime(cfg.ConnectionLifetime)

	return &database{db: db}, nil
}

func (d *database) DB() *gorm.DB {
	return d.db
}

func (d *database) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (d *database) Ping() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func (d *database) AutoMigrate() error {
	return d.db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.OAuthProvider{},
		&models.UserToken{},
		&models.N8NWebhook{},
		&models.Conversation{},
		&models.Message{},
	)
}

type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, keys ...string) (int64, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
	Ping(ctx context.Context) error
	Close() error
}

type redisClient struct {
	client *redis.Client
}

func InitializeRedis(cfg config.RedisConfig) (RedisClient, error) {
	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis URL: %w", err)
	}

	if cfg.Password != "" {
		opt.Password = cfg.Password
	}
	opt.MaxRetries = cfg.MaxRetries
	opt.PoolSize = cfg.PoolSize

	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &redisClient{client: client}, nil
}

func (r *redisClient) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *redisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *redisClient) Delete(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

func (r *redisClient) Exists(ctx context.Context, keys ...string) (int64, error) {
	return r.client.Exists(ctx, keys...).Result()
}

func (r *redisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	return r.client.TTL(ctx, key).Result()
}

func (r *redisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *redisClient) Close() error {
	return r.client.Close()
}

// Connect creates a database connection and returns a Database interface
func Connect(cfg *config.DatabaseConfig) (Database, error) {
	return Initialize(*cfg)
}

// Migrate runs database migrations on a gorm.DB instance
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.OAuthProvider{},
		&models.UserToken{},
		&models.N8NWebhook{},
		&models.Conversation{},
		&models.Message{},
	)
}