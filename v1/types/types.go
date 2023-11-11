package types

import (
	// fiber "github.com/gofiber/fiber/v2"
)

type RedisConfig struct {
	Host string `json:"host"`
	Port string `json:"port"`
	DB int "json:db"
	Password string "json:password"
}

type ConfigFile struct {
	ServerBaseUrl string `json:"server_base_url"`
	ServerPort string `json:"server_port"`
	TimeZone string `json:"time_zone"`
	ServerAPIKey string `json:"server_api_key"`
	ServerCookieName string `json:"server_cookie_name"`
	ServerCookieSecret string `json:"server_cookie_secret"`
	ServerCookieAdminSecretMessage string `json:"server_cookie_admin_secret_message"`
	ServerCookieSecretMessage string `json:"server_cookie_secret_message"`
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
	SecretBoxKey string `json:"secret_box_key"`
	IPBlacklist []string `json:"ip_blacklist"`
	RateLimitPerSecond int `json:"rate_limit_per_second"`
	BoltDBPath string `json:"bolt_db_path"`
}

type AListResponse struct {
	UUIDS []string `json:"uuids"`
}

type RedisMultiCommand struct {
	Command string `json:"type"`
	Key string `json:"key"`
	Args string `json:"args"`
}