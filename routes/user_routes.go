package routes

import (
	"user-service-go/controllers"
	"user-service-go/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(r *gin.Engine) {
	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)

	auth := r.Group("/")
	auth.Use(middleware.AuthMiddleware())
	{

		auth.DELETE("/account", controllers.DeleteAccount)
		auth.PUT("/account", controllers.EditAccount)
	}
}
