package dto

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/scarecrow-404/banking-auth/domain"
)

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() error {
	
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(r.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})

	if err != nil {
		return err
	}


	return nil
}