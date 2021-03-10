package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dochean/cryptogate/models"
	"github.com/dochean/tools/bicrypto"
	"time"

	//"github.com/dochean/tools/log"
	"github.com/AlbinoGeek/logxi/v1"
	"github.com/gorilla/mux"
	"net/http"
	jwt "github.com/dgrijalva/jwt-go"
)

type (
	Response struct {
		Code int         `json:"code"`
		Data interface{} `json:"data"`
	}
	ServerHelloTicket struct {
		Id        string `json:"id"`
		ServerKey []byte `json:"server_key"`
	}
	TokenClaims struct {
		Account string `json:"account"`
		Type string `json:"type"`
		jwt.StandardClaims
	}
	Token struct {
		Check *jwt.Token `json:"check"`
		Refresh *jwt.Token `json:"refresh"`
	}
)

var (
	logger = log.New("mux")

	bm = bicrypto.NewBiManager()

	EXPIRATION_CHECK = time.Hour * 24
	EXPIRATION_REFRESH = time.Hour * 24 * 7
	SECRET_KEY = "everybody know"
)

func main() {
	// router
	router := mux.NewRouter()

	auth := router.PathPrefix("/auth/v1").Subrouter()

	// POST /auth/v1/pubkey { pkey:* } return id, pkey[pubkey]
	auth.HandleFunc("/hello", ServerHello).Methods("POST")
	// POST /auth/v1/access { id; pubkey[authentication]} return pkey[refresh_token, toekn]
	auth.HandleFunc("/access", Access).Methods("POST")
	// POST /auth/v1/refresh { pubkey[refresh_token] } return pkey[token]
	auth.HandleFunc("/refresh", Refresh).Methods("POST")

	// GET /auth/v1/check?token=xxx return bool
	auth.HandleFunc("/check", Check).Methods("GET")

	// POST /auth/v1/encrypt [pubkey]
	// for testing
	auth.HandleFunc("/encrypt", Encrypt)

	logger.Fatal("Server Down:", http.ListenAndServe(":8080", router))
}

func Access(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	cipherBase := r.FormValue("account")
	// base64与密文冲突，导致decrypt失败，有成功案例
	cipher, _ := base64.StdEncoding.DecodeString(cipherBase)
	account, err := bm.Decrypt(id, []byte(cipher))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("Decrypt client msg error: ", err)
		return
	}
	// validate
	var user *models.Account
	err = json.Unmarshal(account, &user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("JSON Decode error: ", err)
		return
	}
	if !user.Authenticate() {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Wrong account or password. Retry please.")
		return
	}
	checkToken := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		Account: user.Name,
		Type: "CHECK",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(EXPIRATION_CHECK).Unix(),
		},
	})
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		Account: user.Name,
		Type: "REFRESH",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(EXPIRATION_REFRESH).Unix(),
		},
	})
	token, err := json.Marshal(Token{
		Check: checkToken,
		Refresh: refreshToken,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("JSON Decode error: ", err)
		return
	}
	cipherToken, err := bm.Encrypt(id, token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("Eecrypt server msg error: ", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	// rsa无法加密太长的信息，需要更换成aes
	// TODO: use aes to encrypt token
	if cipherToken == nil {
		json.NewEncoder(w).Encode(Response{
			Code: 200,
			Data: token,
		})
		return
	}
	json.NewEncoder(w).Encode(Response{
		Code: 200,
		Data: cipherToken,
	})
}

func ServerHello(w http.ResponseWriter, r *http.Request) {
	clientKey := r.FormValue("clientkey")
	if len(clientKey) == 0 {
		// clientkey validation
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, serverKey := bm.Add([]byte(clientKey))
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ServerHelloTicket{Id: id, ServerKey: serverKey})
}

func Check(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	tokenStr, ok := v["token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return []byte(SECRET_KEY), nil
	})
	if err!=nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if claims, ok := token.Claims.(*TokenClaims); !ok || !token.Valid {
		w.WriteHeader(http.StatusBadRequest)
		logger.Info("Token check: ", claims)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	cipher := r.FormValue("refresh")
	id := r.FormValue("id")

	tokenStr, err := bm.Decrypt(id, []byte(cipher))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token, err := jwt.ParseWithClaims(string(tokenStr), &TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return []byte(SECRET_KEY), nil
	})
	if err!=nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var claims *TokenClaims
	var ok bool
	if claims, ok = token.Claims.(*TokenClaims); !ok || !token.Valid {
		w.WriteHeader(http.StatusBadRequest)
		logger.Info("Bad token check: ", claims)
		return
	}
	checkToken := jwt.NewWithClaims(jwt.SigningMethodHS256, TokenClaims{
		Account: claims.Account,
		Type: "CHECK",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(EXPIRATION_CHECK).Unix(),
		},
	})
	tokenJSON, err := json.Marshal(checkToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("JSON Decode error: ", err)
		return
	}
	tokenCipher, err := bm.Encrypt(id, tokenJSON)
	if err!= nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Code: 200,
		Data: tokenCipher,
	})
}

func Encrypt(w http.ResponseWriter, r *http.Request) {
	pubkey := r.FormValue("pubkey")
	msg := r.FormValue("msg")
	crypto := bicrypto.NewRSAByPublicKey([]byte(pubkey))
	cipher := crypto.Encrypt([]byte(msg))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Code: 200,
		Data: cipher,
	})
}