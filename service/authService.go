package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/scarecrow-404/banking-auth/domain"
	"github.com/scarecrow-404/banking-auth/dto"
	"github.com/scarecrow-404/banking-auth/errs"
	"github.com/scarecrow-404/banking-auth/logger"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo domain.AuthRepository
	rolePermission domain.RolePermission
}

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse,*errs.AppError){
	if validateErr := request.IsAccessTokenValid(); validateErr !=nil {
		if validateErr == jwt.ErrTokenExpired {
			var appErr *errs.AppError
			if appErr = s.repo.Refresh(request.RefreshToken) ; appErr != nil{
				return nil, appErr
			}
			var accessToken string
			if accessToken,appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil{
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("invalid token")
	}
	return nil,errs.NewAuthenticationError("can't generate access token")
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse,*errs.AppError){
	var appErr *errs.AppError
	var login *domain.Login

	if login,appErr = s.repo.FindBy(req.Username,req.Username); appErr != nil{
		return nil, appErr
	}
	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)
	var accessToken,refreshToken string
	if accessToken,appErr = authToken.NewAccessToken(); appErr != nil{
		return nil,appErr
	}
	if refreshToken,appErr = authToken.NewRefreshToken(); appErr != nil{
		return nil,appErr
	}
	return &dto.LoginResponse{AccessToken: accessToken,RefreshToken: refreshToken}, nil
	
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error){
	token,err := jwt.ParseWithClaims(tokenString,&domain.AccessTokenClaims{},func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET),nil
	})
	if err != nil {
		logger.Error("Error while parsing token" + err.Error())
		return nil, err
	}

	return token, nil
}

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError{
	if jwtToken,err := jwtTokenFromString(urlParams["token"]); err != nil {
		logger.Error("Error while parsing token" + err.Error())
		return errs.NewAuthenticationError("invalid token")
	} else {
		if jwtToken.Valid{
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams){
					return errs.NewAuthenticationError("unauthorized request (not verified with token claims)")
				}
			}
			isAutherized := s.rolePermission.HasPermission(claims.Role,urlParams["route"])
			if !isAutherized {
				return errs.NewAuthenticationError("unauthorized request")
			}
			return nil
		} else {
			return errs.NewAuthenticationError("invalid token")
		}
	}

}

func NewAuthService(repo domain.AuthRepository,rolePermission domain.RolePermission) DefaultAuthService{
	return DefaultAuthService{
		repo: repo,
		rolePermission: rolePermission,
	}
}