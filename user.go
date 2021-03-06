package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"strconv"

	"errors"

	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

const (
	dbUser          = "anyuser"
	dbPassword      = "anypassword"
	dbName          = "anydbname"
	serverPort      = 12345
	tokenExpiration = 24 //24hrs
)

//User ...
type User struct {
	ID        string `json:"id,omitempty"`
	Firstname string `json:"firstname,omitempty"`
	Lastname  string `json:"lastname,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

//SqlDB ...
var SqlDB *sql.DB
var dbDSN = dbUser + ":" + dbPassword + "@/" + dbName + "?charset=utf8"
var internalError = errors.New("internal error")
var signingKey = []byte("secret")

func tokenValidity(rawToken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("Invalid")
}

/*
* DB functions
 */
func getUserByUsername(username string) (User, error) {

	var user User
	var err error

	err = SqlDB.QueryRow("select id,firstname,lastname,username,password from user where username=?", username).Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Username, &user.Password)
	if err != nil && err != sql.ErrNoRows {
		return user, internalError
	}

	return user, err
}

func getUsers() ([]User, error) {

	var sqlDBRows *sql.Rows
	var err error

	sqlDBRows, err = SqlDB.Query("SELECT id,firstname,lastname FROM user")
	if err != nil {
		return nil, internalError
	}

	var users []User

	for sqlDBRows.Next() {

		var user = User{}

		sqlDBRows.Scan(&user.ID, &user.Firstname, &user.Lastname)

		users = append(users, user)
	}
	return users, nil
}

func getUserByID(id int) (User, error) {

	var user User
	var err error

	err = SqlDB.QueryRow("select id,firstname,lastname from user where id=?", id).Scan(&user.ID, &user.Firstname, &user.Lastname)
	if err != nil && err != sql.ErrNoRows {
		return user, internalError
	}

	return user, err
}

func deleteUserByID(id int) error {
	var sqlDBStmt *sql.Stmt
	var err error

	sqlDBStmt, err = SqlDB.Prepare("delete from user where id=?")
	if err != nil {
		return internalError
	}

	_, err = sqlDBStmt.Exec(id)
	if err != nil {
		return internalError
	}
	return nil
}

func createUser(user User) (User, error) {
	var sqlDBStmt *sql.Stmt
	var sqlDBRslt sql.Result
	var err error

	sqlDBStmt, err = SqlDB.Prepare("insert user set firstname=?,lastname=?")
	if err != nil {
		return user, internalError
	}

	sqlDBRslt, err = sqlDBStmt.Exec(user.Firstname, user.Lastname)
	if err != nil {
		return user, internalError
	}

	var newID int64
	newID, err = sqlDBRslt.LastInsertId()
	if err != nil {
		return user, internalError
	}

	user.ID = strconv.FormatInt(newID, 10)

	return user, nil
}

func updateUser(user User) (User, error) {
	var sqlDBStmt *sql.Stmt
	var err error

	sqlDBStmt, err = SqlDB.Prepare("update user set firstname=?,lastname=? where id=?")
	if err != nil {
		return user, err
	}

	var sqlDBRslt sql.Result
	sqlDBRslt, err = sqlDBStmt.Exec(user.Firstname, user.Lastname, user.ID)
	if err != nil {
		return user, err
	}

	var numOfRecordsUpdated int64
	numOfRecordsUpdated, err = sqlDBRslt.RowsAffected()
	if err != nil {
		return user, err
	}

	if numOfRecordsUpdated > 0 {
		var userID int
		userID, err = strconv.Atoi(user.ID)
		if err != nil {
			return user, err
		}
		user, err = getUserByID(userID)
	}

	return user, err
}

/*
* REST API Endpoints
 */

func tokenAPI(w http.ResponseWriter, req *http.Request) {

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	fmt.Println("use post")
	fmt.Println(user)

	existingUser, err := getUserByUsername(user.Username)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusUnauthorized)
		return
	} else if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(user.Password))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Println("firstname f:", existingUser.Firstname)
	fmt.Println("lastname f:", existingUser.Lastname)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"firstname": existingUser.Firstname,
		"lastname":  existingUser.Lastname,
		"exp":       time.Now().Add(time.Hour * tokenExpiration).Unix(),
	})

	//Sign the token with secret
	tokenString, err := token.SignedString(signingKey)
	if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Write([]byte(tokenString))
	}

}

func getUsersAPI(w http.ResponseWriter, req *http.Request) {
	users, err := getUsers()
	if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		json.NewEncoder(w).Encode(users)
	}
}

func getUserAPI(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)

	userID, err := strconv.Atoi(params["id"])

	user, err := getUserByID(userID)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
	} else if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		json.NewEncoder(w).Encode(user)
	}

}

func createUserAPI(w http.ResponseWriter, req *http.Request) {

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	user, err := createUser(user)
	if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		json.NewEncoder(w).Encode(user)
	}
}

func deleteUserAPI(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)

	userID, err := strconv.Atoi(params["id"])

	if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		err := deleteUserByID(userID)
		if err == internalError {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

}

func updateUserAPI(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)

	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	user.ID = params["id"]

	user, err := updateUser(user)
	if err == internalError {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		json.NewEncoder(w).Encode(user)
	}
}

//middleware for checking authorize token
func tokenMiddleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	//dont include token endpoint
	if r.URL.Path == "/token" {
		next(rw, r)
		return
	}

	//check jwt token
	authorization := r.Header.Get("Authorization")
	if len(authorization) < 1 {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	bearerToken := strings.Split(authorization, " ")
	if bearerToken[0] != "Bearer" {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := bearerToken[1]
	_, err := tokenValidity(token)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	next(rw, r)
}

func main() {
	//db
	var err error

	SqlDB, err = sql.Open("mysql", dbDSN)
	if err != nil {
		panic(err)
	}

	err = SqlDB.Ping()
	if err != nil {
		panic(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/token", tokenAPI).Methods("POST")
	router.HandleFunc("/user", getUsersAPI).Methods("GET")
	router.HandleFunc("/user/{id}", getUserAPI).Methods("GET")
	router.HandleFunc("/user", createUserAPI).Methods("POST")
	router.HandleFunc("/user/{id}", deleteUserAPI).Methods("DELETE")
	router.HandleFunc("/user/{id}", updateUserAPI).Methods("PUT")

	//add token authorization filtering
	n := negroni.New(negroni.HandlerFunc(tokenMiddleware))
	n.UseHandler(router)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", serverPort), n))
	defer SqlDB.Close()

}
