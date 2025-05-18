package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	defaults  map[string]interface{}
	envPrefix string
}

type Option func(*Config)

func WithEnv(prefix string) Option {
	return func(c *Config) {
		if prefix != "" {
			c.envPrefix = prefix + "_"
		}
	}
}

func WithDefault(d map[string]interface{}) Option {
	return func(c *Config) {
		c.defaults = d
	}
}

func New(opts ...Option) (*Config, error) {
	c := &Config{defaults: map[string]interface{}{}}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (c *Config) envKey(key string) string {
	if c.envPrefix != "" {
		return c.envPrefix + strings.ToUpper(key)
	}
	return strings.ToUpper(key)
}

func (c *Config) GetStringWithDefault(key, def string) string {
	if v, ok := os.LookupEnv(c.envKey(key)); ok && v != "" {
		return v
	}
	if val, ok := c.defaults[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return def
}

func (c *Config) GetBool(key string) bool {
	return c.GetBoolWithDefault(key, false)
}

func (c *Config) GetBoolWithDefault(key string, def bool) bool {
	if v, ok := os.LookupEnv(c.envKey(key)); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	if val, ok := c.defaults[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return def
}
