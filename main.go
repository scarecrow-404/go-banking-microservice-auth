package main

import (
	"github.com/scarecrow-404/banking-auth/app"
	"github.com/scarecrow-404/banking-auth/logger"
)

func main() {
	logger.Info(". . . . Starting the application . . . .")
	app.Start()
}