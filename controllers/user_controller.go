package controllers

import (
	"net/http"
	"user-service-go/config"
	"user-service-go/models"
	"user-service-go/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	err = config.DB.QueryRow(
		"INSERT INTO users (username, password, email, role_id) VALUES ($1, $2, $3, $4) RETURNING id",
		user.Username, string(hashedPassword), user.Email, user.RoleID).Scan(&user.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", user.RoleID).Scan(&roleName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve role name"})
		return
	}

	token, _ := utils.GenerateJWT(user.ID, roleName)
	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

func Login(c *gin.Context) {
	var input models.User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := config.DB.QueryRow("SELECT id, password, role_id FROM users WHERE username=$1", input.Username).
		Scan(&user.ID, &user.Password, &user.RoleID)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", user.RoleID).Scan(&roleName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve role name"})
		return
	}

	token, _ := utils.GenerateJWT(user.ID, roleName)
	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

func DeleteAccount(c *gin.Context) {
	userID := c.GetInt("user_id")
	_, err := config.DB.Exec("DELETE FROM users WHERE id=$1", userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Deletion failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account deleted"})
}

func EditAccount(c *gin.Context) {
	userID := c.GetInt("user_id")
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := config.DB.Exec("UPDATE users SET username=$1, email=$2, role_id=$3 WHERE id=$4",
		user.Username, user.Email, user.RoleID, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account updated"})
}
