package utils

import (
    "time"
    "github.com/golang-jwt/jwt"
    "os"
)

func GenerateJWT(userId int, role string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userId,
        "role": role,
        "exp": time.Now().Add(time.Hour * 1).Unix(),
    })

    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
