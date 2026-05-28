package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DBHost                   string
	DBPort                   string
	DBUser                   string
	DBPassword               string
	DBName                   string
	DBMaxOpenConns           int
	DBMaxIdleConns           int
	DBConnMaxLifetimeMinutes int
	AppPort                  string
	AppEnv                   string
	OLTPollIntervalSeconds   int
}

func Load() *Config {
	return &Config{
		DBHost:                   getEnv("DB_HOST", "localhost"),
		DBPort:                   getEnv("DB_PORT", "3306"),
		DBUser:                   getEnv("DB_USER", "mikrotik"),
		DBPassword:               getEnv("DB_PASSWORD", "mikrotik123"),
		DBName:                   getEnv("DB_NAME", "mikrotik_ppp"),
		DBMaxOpenConns:           getEnvInt("DB_MAX_OPEN_CONNS", 40),
		DBMaxIdleConns:           getEnvInt("DB_MAX_IDLE_CONNS", 10),
		DBConnMaxLifetimeMinutes: getEnvInt("DB_CONN_MAX_LIFETIME_MINUTES", 10),
		AppPort:                  getEnv("APP_PORT", "8080"),
		AppEnv:                   getEnv("APP_ENV", "development"),
		OLTPollIntervalSeconds:   getEnvInt("OLT_POLL_INTERVAL_SECONDS", 60),
	}
}

func (c *Config) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FJakarta&time_zone=%%27%%2B07:00%%27",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
