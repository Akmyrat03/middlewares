package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var jwtKey = []byte("secret_key")

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.StandardClaims
}

func GenerateJWT(userID int, email string) (string, error) {
	expirationTime := time.Now().Add(time.Hour * 24)
	claims := &Claims{
		UserID: userID,
		Email:  email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// token olustur
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// imzala
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Token'i header'den al
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token bulunamdi",
			})
			c.Abort()
			return
		}

		// 'Bearer' kismini ayirarak sadece token'i aliriz
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}

		// Token'in icindeki bilgileri cikartiyoruz
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Gecersiz veya suresi dolmus token",
			})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)

		c.Next()
	}
}

func main() {
	token, err := GenerateJWT(10, "akmyrat@test.com")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Println("Token: ", token)

	r := gin.Default()

	r.GET("/profile", Authentication(), func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		email, _ := c.Get("email")

		c.JSON(200, gin.H{
			"user_id": userID,
			"email":   email,
		})
	})

	r.Run(":8080")
}
