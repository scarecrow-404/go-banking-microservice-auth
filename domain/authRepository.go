package domain

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/scarecrow-404/banking-auth/errs"
	"github.com/scarecrow-404/banking-auth/logger"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *errs.AppError)
	GenerateTokenToStore(authToken AuthToken) (string, *errs.AppError)
	Refresh(refreshToken string) *errs.AppError
}

type AuthRepositoryDB struct{
	client *sqlx.DB
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryDB {
	return AuthRepositoryDB{client: client}
}

func (d AuthRepositoryDB) Refresh(refreshToken string)  *errs.AppError {
	sqlQuery := "select refresh_token from refresh_token_store where refresh_token = $1"
	var token string
	err := d.client.Get(&token, sqlQuery, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewNotFoundError("refresh token not found")
		} else {
			logger.Error("Error while scanning token:" + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}
	return nil
}

func (d AuthRepositoryDB) GenerateTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken,appErr = authToken.NewRefreshToken(); appErr != nil {
		return "", appErr
	}

	sqlQuery := "insert into refresh_token_store (refresh_token) values ($1)"
	_, err := d.client.Exec(sqlQuery, refreshToken)
	if err != nil {
		logger.Error("Error while saving token:" + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}

func (d AuthRepositoryDB) FindBy(username,password string) (*Login,*errs.AppError){
	var login Login
	sqlQuery := `SELECT username, u.customer_id AS user_customer_id, role, group_concat(a.account_id) AS account_ids
	FROM users u
	LEFT JOIN accounts a ON a.customer_id = u.customer_id
	WHERE username = $1 AND password = $2`
	err := d.client.Get(&login, sqlQuery, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewNotFoundError("user not found")
		} else {
			logger.Error("Error while scanning user:" + err.Error())
			return nil, errs.NewUnexpectedError("unexpected database error")
		}
	}
	return &login, nil
}