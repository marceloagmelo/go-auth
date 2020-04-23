package main

import (
	"github.com/marceloagmelo/go-auth/logger"

	"github.com/marceloagmelo/go-auth/app"
	"github.com/marceloagmelo/go-auth/config"
)

func main() {
	config := config.GetConfig()

	app := &app.App{}
	app.Initialize(config)
	logger.Info.Println("Listen 8080...")
	app.Run(":8080")
}
