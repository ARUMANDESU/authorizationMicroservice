package jwt

import (
	"authorizationMicroservice/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	user := models.User{
		ID:       1,
		Email:    "test@mail.com",
		PassHash: []byte("$2a$10$R6Vl7I2JruchjaKYOKb1C.Vp18sJjSSzJXYWMbTA/pquHXlDn1kF2"),
	}

	app := models.App{
		ID:     1,
		Name:   "app1",
		Secret: "test1",
	}
	duration := time.Hour

	tokenString, err := NewToken(&user, &app, duration)
	if err != nil {
		t.Errorf("NewToken returned an unexpected error: %v", err)
	}

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(app.Secret), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if uid, ok := claims["uid"].(float64); !ok || int64(uid) != user.ID {
			t.Errorf("Expected uid claim to be %v, got %v", user.ID, claims["uid"])
		}
		// Check email claim
		if claims["email"] != user.Email {
			t.Errorf("Expected email claim to be %v, got %v", user.Email, claims["email"])
		}
		// Check app ID claim
		if appID, ok := claims["app_id"].(float64); !ok && int64(appID) != app.ID {
			t.Errorf("Expected app_id claim to be %v, got %v", app.ID, claims["app_id"])
		}
		// Check the expiration time
		if exp, ok := claims["exp"].(float64); !ok || time.Unix(int64(exp), 0).Sub(time.Now()) > duration {
			t.Errorf("Expected exp claim to be within %v, got %v", duration, exp)
		}
	} else {
		t.Errorf("Token parsing or validation failed: %v", err)
	}

}
