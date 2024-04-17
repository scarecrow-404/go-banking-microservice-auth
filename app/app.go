package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/scarecrow-404/banking-auth/domain"
	"github.com/scarecrow-404/banking-auth/logger"
	"github.com/scarecrow-404/banking-auth/service"
)

func Start() {
	sanityCheck()
	router := mux.NewRouter()
	authRepository := domain.NewAuthRepository(getDbClient())
	ah := AuthHandler{service.NewAuthService(authRepository,domain.GetRolePermission())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/refresh", ah.Refresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	
	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	addressPort := fmt.Sprintf("%s:%s", address, port)
	fmt.Println("Starting server on", addressPort)
	log.Fatal(http.ListenAndServe(addressPort, router))

}

func sanityCheck() {
	envVariable := []string{
		"SERVER_ADDRESS", "SERVER_PORT", "DB_USER", "DB_PASSWD", "DB_HOST", "DB_PORT", "DB_NAME",
	}
	for _, v := range envVariable {
		if os.Getenv(v) == "" {
			logger.Fatal(fmt.Sprintf("Environment variable %s not defined. Terminating application...", v))
		}
	}
}

func getDbClient() *sqlx.DB{
	host     := os.Getenv("DB_HOST")
    port     := os.Getenv("DB_PORT")
	user     := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWD")
	dbname   := os.Getenv("DB_NAME")


	psqlconn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	
    db, err := sqlx.Open("postgres", psqlconn)
	if err !=nil{
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute *3)
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(20)
	return db
}
