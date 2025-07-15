package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type OIDCConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	IssuerURL    string `json:"issuer_url"`
	RedirectURL  string `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

type Config struct {
	OIDC OIDCConfig `json:"oidc"`
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Session struct {
		Secret     string `json:"secret"`
		MaxAge     int    `json:"max_age"` // in seconds
		Secure     bool   `json:"secure"`
		HttpOnly   bool   `json:"http_only"`
	} `json:"session"`
	User struct {
		HomeDirBase string `json:"home_dir_base"`
		Shell       string `json:"shell"`
	} `json:"user"`
}

func LoadConfig(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = "config.json"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

func DefaultConfig() *Config {
	config := &Config{}
	
	config.OIDC.Scopes = []string{"openid", "profile", "email"}
	config.Server.Host = "localhost"
	config.Server.Port = 8080
	config.Session.Secret = "your-secret-key-change-this-in-production"
	config.Session.MaxAge = 86400 // 24 hours
	config.Session.Secure = false
	config.Session.HttpOnly = true
	config.User.HomeDirBase = "/home"
	config.User.Shell = "/bin/bash"
	
	return config
}

func validateConfig(config *Config) error {
	if config.OIDC.ClientID == "" {
		return fmt.Errorf("OIDC client_id is required")
	}
	if config.OIDC.ClientSecret == "" {
		return fmt.Errorf("OIDC client_secret is required")
	}
	if config.OIDC.IssuerURL == "" {
		return fmt.Errorf("OIDC issuer_url is required")
	}
	if config.OIDC.RedirectURL == "" {
		return fmt.Errorf("OIDC redirect_url is required")
	}
	if config.Session.Secret == "" {
		return fmt.Errorf("session secret is required")
	}
	return nil
}