package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const HMAC_SAMPLE_SECRET = "sampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour
const REFRESH_TOKEN_DURATION = 30 * 24 * time.Hour

type RefreshTokenClaims struct {
	tokenType  string   `json:"token_type"`
	customerId string   `json:"cid"`
	account    []string `json:"accounts"`
	role       string   `json:"role"`
	username string `json:"un"`
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	CustomerId string `json:"customer_id"`
	Accounts []string `json:"accounts"`
	Username string `json:"username"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func (c AccessTokenClaims) IsUserRole() bool{
	return c.Role == "user"
}

func (c AccessTokenClaims) IsValidCustomerId(customerId string) bool{
	return c.CustomerId == customerId
}

func (c AccessTokenClaims) IsValidAccountId(accountId string) bool {
	if accountId != ""{
		accountFound := false 
		for _, account := range c.Accounts{
			if account == accountId{
				accountFound = true
				break
			}
		}
		return accountFound
	}
	return true
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool{
	if c.CustomerId != urlParams["customer_id"]{
		return false
	}
	if !c.IsValidAccountId(urlParams["account_id"]){
		return false
	}
	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims{
	return RefreshTokenClaims{
		tokenType:  "refresh_token",
		customerId: c.CustomerId,
		account:    c.Accounts,
		role:       c.Role,
		username:   c.Username,
		RegisteredClaims:  jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(REFRESH_TOKEN_DURATION)),
		},
	}
}


func (c AccessTokenClaims) AccessTokenClaims() AccessTokenClaims{
	return AccessTokenClaims{
		CustomerId: c.CustomerId,
		Accounts:   c.Accounts,
		Username:   c.Username,
		Role:       c.Role,
		RegisteredClaims:  jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ACCESS_TOKEN_DURATION)),
		},
	}
}