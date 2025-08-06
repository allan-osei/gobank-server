package main

import (
	"log"
	"os"

	"github.com/spf13/viper"
)

func LoadConfig() {
	// Load .env file ONLY in local development
	if os.Getenv("RAILWAY_ENVIRONMENT") == "" {
		viper.SetConfigFile(".env")
		err := viper.ReadInConfig()
		if err != nil {
			log.Println("⚠️ No .env file found (expected in Railway)")
		} else {
			log.Println("✅ .env file loaded")
		}
	}

	viper.AutomaticEnv() // always load real environment variables (Railway injects them)
}
