package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	App       AppConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	Security  SecurityConfig
	OpenAI    OpenAIConfig
	OAuth     OAuthConfig
	N8N       N8NConfig
	RateLimit RateLimitConfig
	Log       LogConfig
	CORS      CORSConfig
	Server    ServerConfig
}

type AppConfig struct {
	Env   string
	Port  int
	Name  string
	Debug bool
}

type DatabaseConfig struct {
	URL                string
	MaxConnections     int
	MaxIdleConnections int
	ConnectionLifetime time.Duration
}

type RedisConfig struct {
	URL        string
	Password   string
	MaxRetries int
	PoolSize   int
}

type SecurityConfig struct {
	EncryptionKey string
	JWTSecret     string
	JWTExpiry     time.Duration
	RefreshExpiry time.Duration
}

type OpenAIConfig struct {
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float32
	// Azure OpenAI specific settings - when Azure.Enabled=true, these settings override standard OpenAI
	Azure AzureOpenAIConfig
}

// AzureOpenAIConfig contains Azure-specific configuration for OpenAI services
// When Enabled=true, the service will use Azure OpenAI instead of standard OpenAI
type AzureOpenAIConfig struct {
	Enabled        bool   // Set to true to use Azure OpenAI instead of standard OpenAI
	Endpoint       string // Azure OpenAI resource endpoint (e.g., https://your-resource.openai.azure.com/)
	APIKey         string // Azure OpenAI API key
	DeploymentName string // Azure OpenAI deployment name (replaces Model when using Azure)
	APIVersion     string // Azure OpenAI API version (e.g., 2024-12-01-preview)
}

type OAuthConfig struct {
	RedirectBaseURL string
	SessionTimeout  time.Duration
}

type N8NConfig struct {
	DefaultTimeout time.Duration
	MaxRetries     int
}

type RateLimitConfig struct {
	Enabled            bool
	RequestsPerMinute  int
	Burst              int
}

type LogConfig struct {
	Level  string
	Format string
	Output string
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

type ServerConfig struct {
	ReadTimeout    int
	WriteTimeout   int
	IdleTimeout    int
	MaxHeaderBytes int
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()

	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var config Config
	
	config.App = AppConfig{
		Env:   viper.GetString("APP_ENV"),
		Port:  viper.GetInt("APP_PORT"),
		Name:  viper.GetString("APP_NAME"),
		Debug: viper.GetBool("APP_DEBUG"),
	}

	config.Database = DatabaseConfig{
		URL:                viper.GetString("DATABASE_URL"),
		MaxConnections:     viper.GetInt("DB_MAX_CONNECTIONS"),
		MaxIdleConnections: viper.GetInt("DB_MAX_IDLE_CONNECTIONS"),
		ConnectionLifetime: time.Duration(viper.GetInt("DB_CONNECTION_LIFETIME_SECONDS")) * time.Second,
	}

	config.Redis = RedisConfig{
		URL:        viper.GetString("REDIS_URL"),
		Password:   viper.GetString("REDIS_PASSWORD"),
		MaxRetries: viper.GetInt("REDIS_MAX_RETRIES"),
		PoolSize:   viper.GetInt("REDIS_POOL_SIZE"),
	}

	config.Security = SecurityConfig{
		EncryptionKey: viper.GetString("ENCRYPTION_KEY"),
		JWTSecret:     viper.GetString("JWT_SECRET"),
		JWTExpiry:     time.Duration(viper.GetInt("JWT_EXPIRY_HOURS")) * time.Hour,
		RefreshExpiry: time.Duration(viper.GetInt("JWT_REFRESH_EXPIRY_DAYS")) * 24 * time.Hour,
	}

	config.OpenAI = OpenAIConfig{
		APIKey:      viper.GetString("OPENAI_API_KEY"),
		Model:       viper.GetString("OPENAI_MODEL"),
		MaxTokens:   viper.GetInt("OPENAI_MAX_TOKENS"),
		Temperature: float32(viper.GetFloat64("OPENAI_TEMPERATURE")),
		Azure: AzureOpenAIConfig{
			Enabled:        viper.GetBool("AZURE_OPENAI_ENABLED"),
			Endpoint:       viper.GetString("AZURE_OPENAI_ENDPOINT"),
			APIKey:         viper.GetString("AZURE_OPENAI_API_KEY"),
			DeploymentName: viper.GetString("AZURE_OPENAI_DEPLOYMENT_NAME"),
			APIVersion:     viper.GetString("AZURE_OPENAI_API_VERSION"),
		},
	}

	config.OAuth = OAuthConfig{
		RedirectBaseURL: viper.GetString("OAUTH_REDIRECT_BASE_URL"),
		SessionTimeout:  time.Duration(viper.GetInt("OAUTH_SESSION_TIMEOUT_MINUTES")) * time.Minute,
	}

	config.N8N = N8NConfig{
		DefaultTimeout: time.Duration(viper.GetInt("N8N_DEFAULT_TIMEOUT_SECONDS")) * time.Second,
		MaxRetries:     viper.GetInt("N8N_MAX_RETRIES"),
	}

	config.RateLimit = RateLimitConfig{
		Enabled:           viper.GetBool("RATE_LIMIT_ENABLED"),
		RequestsPerMinute: viper.GetInt("RATE_LIMIT_REQUESTS_PER_MINUTE"),
		Burst:             viper.GetInt("RATE_LIMIT_BURST"),
	}

	config.Log = LogConfig{
		Level:  viper.GetString("LOG_LEVEL"),
		Format: viper.GetString("LOG_FORMAT"),
		Output: viper.GetString("LOG_OUTPUT"),
	}

	config.CORS = CORSConfig{
		AllowedOrigins:   viper.GetStringSlice("CORS_ALLOWED_ORIGINS"),
		AllowedMethods:   viper.GetStringSlice("CORS_ALLOWED_METHODS"),
		AllowedHeaders:   viper.GetStringSlice("CORS_ALLOWED_HEADERS"),
		ExposeHeaders:    viper.GetStringSlice("CORS_EXPOSE_HEADERS"),
		AllowCredentials: viper.GetBool("CORS_ALLOW_CREDENTIALS"),
		MaxAge:           viper.GetInt("CORS_MAX_AGE"),
	}

	config.Server = ServerConfig{
		ReadTimeout:    viper.GetInt("SERVER_READ_TIMEOUT_SECONDS"),
		WriteTimeout:   viper.GetInt("SERVER_WRITE_TIMEOUT_SECONDS"),
		IdleTimeout:    viper.GetInt("SERVER_IDLE_TIMEOUT_SECONDS"),
		MaxHeaderBytes: viper.GetInt("SERVER_MAX_HEADER_BYTES"),
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("APP_PORT", 8080)
	viper.SetDefault("APP_NAME", "ai-orchestrator")
	viper.SetDefault("APP_DEBUG", false)
	
	viper.SetDefault("DB_MAX_CONNECTIONS", 100)
	viper.SetDefault("DB_MAX_IDLE_CONNECTIONS", 10)
	viper.SetDefault("DB_CONNECTION_LIFETIME_SECONDS", 300)
	
	viper.SetDefault("REDIS_MAX_RETRIES", 3)
	viper.SetDefault("REDIS_POOL_SIZE", 10)
	
	viper.SetDefault("JWT_EXPIRY_HOURS", 24)
	viper.SetDefault("JWT_REFRESH_EXPIRY_DAYS", 7)
	
	viper.SetDefault("OPENAI_MODEL", "gpt-4-turbo-preview")
	viper.SetDefault("OPENAI_MAX_TOKENS", 2000)
	viper.SetDefault("OPENAI_TEMPERATURE", 0.7)
	
	viper.SetDefault("AZURE_OPENAI_ENABLED", false)
	viper.SetDefault("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
	
	viper.SetDefault("OAUTH_SESSION_TIMEOUT_MINUTES", 10)
	
	viper.SetDefault("N8N_DEFAULT_TIMEOUT_SECONDS", 30)
	viper.SetDefault("N8N_MAX_RETRIES", 3)
	
	viper.SetDefault("RATE_LIMIT_ENABLED", true)
	viper.SetDefault("RATE_LIMIT_REQUESTS_PER_MINUTE", 60)
	viper.SetDefault("RATE_LIMIT_BURST", 10)
	
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("LOG_FORMAT", "json")
	viper.SetDefault("LOG_OUTPUT", "stdout")
	
	viper.SetDefault("CORS_MAX_AGE", 300)
	
	viper.SetDefault("SERVER_READ_TIMEOUT_SECONDS", 30)
	viper.SetDefault("SERVER_WRITE_TIMEOUT_SECONDS", 30)
	viper.SetDefault("SERVER_IDLE_TIMEOUT_SECONDS", 60)
	viper.SetDefault("SERVER_MAX_HEADER_BYTES", 1048576)
}