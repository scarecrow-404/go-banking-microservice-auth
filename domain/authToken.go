package domain

import (
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/scarecrow-404/banking-auth/errs"
	"github.com/scarecrow-404/banking-auth/logger"
)

type AuthToken struct {
	token *jwt.Token
}

func getSecret() string {
	secret := os.Getenv("SECRET")
	return secret
}

func (t AuthToken) NewAccessToken() (string, *errs.AppError) {

	signedString,err := t.token.SignedString([]byte(getSecret()))
	if err != nil {
		logger.Error("Error while signing token" + err.Error())
		return "", errs.NewUnexpectedError("can't generate access token")
}
return signedString,nil
}

func (t AuthToken) NewRefreshToken() (string, *errs.AppError) {
	
	signedString,err := t.token.SignedString([]byte(getSecret()))
	if err != nil {
		logger.Error("Error while signing token" + err.Error())
		return "", errs.NewUnexpectedError("can't generate refresh token")
}
return signedString,nil
}

func NewAuthToken(claims jwt.Claims) AuthToken {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"),claims)
	return AuthToken{token: token}
}

func NewAccessTokenFromRefreshToken(refreshToken string) (string, *errs.AppError){
	token,err := jwt.ParseWithClaims(refreshToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(getSecret()), nil
	})

	if err != nil {
		logger.Error("Error while parsing token" + err.Error())
		return "", errs.NewUnexpectedError("can't generate access token")
	}
	claims := token.Claims.(jwt.MapClaims)
	return NewAuthToken(claims).NewAccessToken()
}
