package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"strconv"

	"errors"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

const (
	dbUser          = "anyuser"
	dbPassword      = "anypassword"
	dbName          = "anydbname"
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"firstname": user.Firstname,
		"lastname":  user.Lastname,
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

	//sample generate password
	//passwordSecret := []byte("supersecret")
	//passwordSecret := []byte("supersecret123")
	/*
		passwordSecret := []byte("supersecret45")

		hashPassword, err := bcrypt.GenerateFromPassword(passwordSecret, bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("error bcryt password", err)
		} else {
			fmt.Println("ok bcryt password")
			fmt.Println(string(hashPassword))

			var sqlDBStmt *sql.Stmt
			var err error

			sqlDBStmt, err = SqlDB.Prepare("update user set password=? where id=5")
			if err != nil {
				panic(err)
			}

			_, err = sqlDBStmt.Exec(string(hashPassword))
			if err != nil {
				panic(err)
			} else {
				fmt.Println("ok genrate password")
			}

			err = bcrypt.CompareHashAndPassword(hashPassword, passwordSecret)
			if err != nil {
				fmt.Println(err) // nil means it is a match
			} else {
				fmt.Println("matched password")
			}
		}*/

	router := mux.NewRouter()

	router.HandleFunc("/token", tokenAPI).Methods("POST")
	router.HandleFunc("/user", getUsersAPI).Methods("GET")
	router.HandleFunc("/user/{id}", getUserAPI).Methods("GET")
	router.HandleFunc("/user", createUserAPI).Methods("POST")
	router.HandleFunc("/user/{id}", deleteUserAPI).Methods("DELETE")
	router.HandleFunc("/user/{id}", updateUserAPI).Methods("PUT")

	log.Fatal(http.ListenAndServe(":12345", router))
	defer SqlDB.Close()
}
