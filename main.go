package main

import (
	"log"
	"user-service-go/config"
	"user-service-go/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	config.Connect()

	r := gin.Default()
	routes.UserRoutes(r)

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
