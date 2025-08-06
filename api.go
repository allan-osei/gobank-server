package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin))
	router.HandleFunc("/logout", makeHTTPHandleFunc(s.handleLogout))
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandleFunc(s.handleGetAccountByID)))
	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	log.Println("JSON API server running on port: ", s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)
}

// 498081
const loginLimitKey = "login_fail:"

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	failKey := fmt.Sprintf("%s%d", loginLimitKey, req.Number)

	// ⛔ Check if login is rate-limited
	count, _ := RedisClient.Get(ctx, failKey).Int()
	if count >= 3 {
		log.Printf("Blocking login for %d: too many failed attempts\n", req.Number)
		return fmt.Errorf("too many failed attempts. try again later")
	}

	// 🔍 Lookup user by account number
	acc, err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		log.Printf("Account %d not found\n", req.Number)
		incrFailCounter(failKey)
		return fmt.Errorf("account not found")
	}

	log.Printf("Validating password. Input: %s, Encrypted: %s\n", req.Password, acc.EncryptedPassword)

	// 🔒 Check password
	if !acc.ValidPassword(req.Password) {
		log.Printf("Password valid? %v\n", acc.ValidPassword(req.Password))
		log.Printf("Invalid password for %d\n", req.Number)
		count := incrFailCounter(failKey)
		if count >= 3 {
			log.Printf("Blocking login for %d: too many failed attempts\n", req.Number)
			return fmt.Errorf("too many failed attempts. try again later")
		}
		return fmt.Errorf("invalid credentials")
	}

	// ✅ Login successful — reset fail counter
	RedisClient.Del(ctx, failKey)

	// 🎟️ Issue JWT
	token, err := createJWT(acc)
	if err != nil {
		return err
	}

	resp := LoginResponse{
		Token:  token,
		Number: acc.Number,
	}

	log.Printf("Successful login for %d. Fail counter reset.\n", req.Number)
	return WriteJSON(w, http.StatusOK, resp)
}

func incrFailCounter(failKey string) int {
	count, err := RedisClient.Incr(ctx, failKey).Result()
	if err != nil {
		log.Printf("Redis INCR failed for key %s: %v", failKey, err)
		return 0
	}
	RedisClient.Expire(ctx, failKey, 1*time.Minute)
	return int(count)
}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccount(w, r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleGetAccount(w http.ResponseWriter, _ *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		id, err := getID(r)
		if err != nil {
			return err
		}

		// Try cache first
		cacheKey := fmt.Sprintf("account:%d", id)
		cached, err := RedisClient.Get(ctx, cacheKey).Result()
		if err == nil && cached != "" {
			log.Println("✅ cache hit for account", id)
			var acc Account
			if err := json.Unmarshal([]byte(cached), &acc); err == nil {
				return WriteJSON(w, http.StatusOK, acc)
			}
		}

		// If not in cache, fetch from DB
		log.Println("🌀 cache miss, querying DB for account", id)
		account, err := s.store.GetAccountByID(id)
		if err != nil {
			return err
		}

		// Cache it for future use (e.g. 60s)
		data, _ := json.Marshal(account)
		RedisClient.Set(ctx, cacheKey, data, time.Minute)

		return WriteJSON(w, http.StatusOK, account)

	}

	if r.Method == "DELETE" {
		return s.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	account, err := NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		return err
	}
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferReq := new(TransferRequest)
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}
	defer r.Body.Close()

	return WriteJSON(w, http.StatusOK, transferReq)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(v)
}

func createJWT(account *Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt":     15000,
		"accountNumber": account.Number, // ✅ using accountNumber now
		"jti":           uuid.NewString(),
	}

	secret := viper.GetString("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(secret))
}

// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50TnVtYmVyIjo0OTgwODEsImV4cGlyZXNBdCI6MTUwMDB9.TdQ907o9yhUI2KU0TngrqO-xbfNgHAfZI6Jngia15UE

func withJWTAuth(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("calling JWT auth middleware")

		tokenString := r.Header.Get("x-jwt-token")
		fmt.Println("Token from header:", tokenString)

		token, err := validateJWT(tokenString)
		if err != nil || !token.Valid {
			fmt.Println("Token validation failed:", err)
			permissionDenied(w)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("Failed to parse JWT claims")
			permissionDenied(w)
			return
		}

		fmt.Println("JWT claims:", claims)

		claimIDFloat, ok := claims["accountID"].(float64)
		if !ok {
			fmt.Println("accountID claim not found or invalid type")
			permissionDenied(w)
			return
		}
		claimID := int(claimIDFloat)
		fmt.Println("accountID from token:", claimID)

		userID, err := getID(r)
		if err != nil {
			fmt.Println("Failed to get ID from URL:", err)
			permissionDenied(w)
			return
		}
		fmt.Println("account ID from URL:", userID)

		if userID != claimID {
			fmt.Printf("Mismatch: token accountID=%d, URL accountID=%d\n", claimID, userID)
			permissionDenied(w)
			return
		}

		jti, ok := claims["jti"].(string)
		if !ok {
			fmt.Println("jti claim missing or not a string")
			permissionDenied(w)
			return
		}
		exists, _ := RedisClient.Get(ctx, "blacklist:"+jti).Result()
		if exists == "true" {
			fmt.Println("JWT token is blacklisted:", jti)
			permissionDenied(w)
			return
		}

		fmt.Println("✅ JWT validated successfully")
		handlerFunc(w, r)

	}
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := viper.GetString("JWT_SECRET")

	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}

// permissionDenied writes a 403 Forbidden response with a JSON error message.
func permissionDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(ApiError{Error: "permission denied"})
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}
	return id, nil
}

func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) error {
	tokenStr := r.Header.Get("x-jwt-token")
	token, err := validateJWT(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	jti := claims["jti"].(string)

	// Blacklist the token by storing the jti in Redis
	err = RedisClient.Set(ctx, "blacklist:"+jti, "true", time.Hour).Err()
	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}
