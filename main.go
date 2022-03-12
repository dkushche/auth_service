package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/dkushche/roothazardlab_backend/internal/account"
	"github.com/dkushche/roothazardlab_backend/internal/token"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func checkAuth(w http.ResponseWriter, r *http.Request) {
	log.Println("checkAuth")

	uyggAddr := r.Header.Get("X-REAL-IP")
	tokenCookie, err := r.Cookie("auth_token")

	if err != nil {
		log.Printf("%w\n", err)
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		log.Println("Has cookie")
		log.Printf("%s\n", tokenCookie.Value)

		auth_token, err := base64.StdEncoding.DecodeString(tokenCookie.Value)
		if err != nil {
			log.Printf("%w\n", err)
		} else {
			err := token.VerifyToken(auth_token, uyggAddr)
			if err != nil {
				log.Println("Invalid token")
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Println("handleLogin")

	uname := r.FormValue("uname")
	upasswd := r.FormValue("upasswd")
	uyggAddr := r.Header.Get("X-REAL-IP")

	uaccount, err := account.Get(uname, upasswd)

	if err != nil {
		log.Printf("%w\n", err)
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		auth_token, err := token.GenerateToken(uaccount, uyggAddr)
		if err != nil {
			log.Printf("%w\n", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			cookie := &http.Cookie{
				Name:     "auth_token",
				Value:    base64.StdEncoding.EncodeToString(auth_token),
				Domain:   "roothazardlab.ygg",
				HttpOnly: true,
			}
			http.SetCookie(w, cookie)

			log.Println("Access granted")
		}
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Println("handleLogout")

	_, err := r.Cookie("auth_token")
	if err == nil {
		cookie := &http.Cookie{
			Name:     "auth_token",
			Value:    "",
			Domain:   "roothazardlab.ygg",
			MaxAge:   -1,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
	} else {
		log.Println("Error occured while reading cookie")
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func createRouter() *mux.Router {
	router := mux.NewRouter()

	router.StrictSlash(true)

	router.HandleFunc("/auth", checkAuth).Methods("GET")
	router.HandleFunc("/login", handleLogin).Methods("POST")
	router.HandleFunc("/logout", handleLogout).Methods("POST")

	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{
			"http://home.roothazardlab.ygg",
		}),
		handlers.AllowedMethods([]string{
			"GET", "POST",
		}),
		handlers.AllowCredentials(),
	)

	router.Use(cors)

	return router
}

func prepareStorage(subDir string) {
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		if err := os.MkdirAll(subDir, os.ModePerm); err != nil {
			log.Println("Can't create logs " + subDir)
			panic("can't create logs " + subDir)
		}
	}
}

func main() {
	router := createRouter()

	prepareStorage("storage/logs")
	file, err := os.OpenFile("storage/logs/logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	log.SetOutput(file)
	log.Println("Logger initialized")

	defer file.Close()

	prepareStorage("storage/db")
	err = account.InitDatabase("storage/db/accounts.db")
	if err != nil {
		panic(err)
	}
	log.Println("Database initialized")

	prepareStorage("storage/keys")
	err = token.InitKey("storage/keys/auth_priv.pem")
	if err != nil {
		panic(err)
	}
	log.Println("Keys initialized")

	http.ListenAndServe(":80", router)
}
