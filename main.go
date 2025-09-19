package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/taham8875/chirpy/internal/auth"
	"github.com/taham8875/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	dbQueries := database.New(db)

	// Create a new HTTP server mux
	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		platform:  os.Getenv("PLATFORM"),
		jwtSecret: os.Getenv("JWT_SECRET"),
		polkaKey:  os.Getenv("POLKA_KEY"),
	}

	fileServer := http.FileServer(http.Dir("."))

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))

	mux.HandleFunc("GET /healthz", readinessHandler)
	mux.HandleFunc("GET /api/healthz", readinessHandler)

	mux.HandleFunc("GET /metrics", apiCfg.metricsHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandlerHTML)

	mux.HandleFunc("POST /reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpByIDHandler)

	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)

	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookHandler)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	log.Println("Starting server on :8080")
	err = server.ListenAndServe()

	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	count := cfg.fileserverHits.Load()
	fmt.Fprintf(w, "Hits: %d\n", count)
}

func (cfg *apiConfig) metricsHandlerHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	count := cfg.fileserverHits.Load()
	html := `
		<html>
		  <body>
		    <h1>Welcome, Chirpy Admin</h1>
		    <p>Chirpy has been visited %d times!</p>
		  </body>
		</html>
                `

	fmt.Fprintf(w, html, count)
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	cfg.fileserverHits.Store(0)

	// delete all users
	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Failed to delete users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0 and all users deleted"))
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type requestBody struct {
		Body string `json:"body"`
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	type successResponse struct {
		CleanedBody string `json:"cleaned_body"`
	}

	params := &requestBody{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Invalid JSON"})
		return
	}

	if len(params.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		response, err := json.Marshal(errorResponse{Error: "Chirp is too long"})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(response)
		return
	}

	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	cleaned := params.Body

	for _, badWord := range profaneWords {
		re := regexp.MustCompile(`\b(?i)` + badWord + `\b`)
		cleaned = re.ReplaceAllString(cleaned, "****")
	}

	w.WriteHeader(http.StatusOK)
	response, err := json.Marshal(successResponse{CleanedBody: cleaned})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(response)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(r.Context())

	if err != nil {
		http.Error(w, "Failed to fetch chirps", http.StatusInternalServerError)
		return
	}

	type responseBody struct {
		ID        string    `json:"id"`
		Body      string    `json:"body"`
		UserID    string    `json:"user_id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	resp := make([]responseBody, 0, len(chirps))

	for _, chirp := range chirps {
		resp = append(resp, responseBody{
			ID:        chirp.ID.String(),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	chirpIDStr := r.PathValue("chirpID")

	chirpsID, err := uuid.Parse(chirpIDStr)

	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpsID)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Chirp not found", http.StatusNotFound)
			return
		}

		http.Error(w, "Failed to fetch chirp", http.StatusInternalServerError)
		return
	}

	type responseBody struct {
		ID        string    `json:"id"`
		Body      string    `json:"body"`
		UserID    string    `json:"user_id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	resp := responseBody{
		ID:        chirp.ID.String(),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) deleteChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr, err := auth.GetBearerToken(r.Header)

	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenStr, cfg.jwtSecret)

	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	chirpIDStr := r.PathValue("chirpID")

	chirpsID, err := uuid.Parse(chirpIDStr)

	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpsID)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Chirp not found", http.StatusNotFound)
			return
		}

		http.Error(w, "Failed to fetch chirp", http.StatusInternalServerError)
		return
	}

	if chirp.UserID != userID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), database.DeleteChirpParams{
		ID:     chirpsID,
		UserID: userID,
	})

	if err != nil {
		http.Error(w, "Failed to delete chirp: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type requestBody struct {
		Body string `json:"body"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	type responseBody struct {
		ID        string `json:"id"`
		Body      string `json:"body"`
		UserId    string `json:"user_id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	token, err := auth.GetBearerToken(r.Header)

	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)

	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	params := &requestBody{}

	err = json.NewDecoder(r.Body).Decode(params)

	if err != nil || params.Body == "" {
		http.Error(w, "Invalid JSON or params", http.StatusBadRequest)
		return
	}

	if len(params.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		response, err := json.Marshal(errorResponse{Error: "Chirp is too long"})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(response)
		return
	}

	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	cleaned := params.Body

	for _, badWord := range profaneWords {
		re := regexp.MustCompile(`\b(?i)` + badWord + `\b`)
		cleaned = re.ReplaceAllString(cleaned, "****")
	}

	now := time.Now()
	newID := uuid.New()

	chirpParams := database.CreateChirpParams{
		ID:        newID,
		Body:      cleaned,
		UserID:    userID,
		CreatedAt: now,
		UpdatedAt: now,
	}

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), chirpParams)

	if err != nil {
		fmt.Println("Error creating chirp:", err)
		http.Error(w, "Failed to create chirp", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		ID:        chirp.ID.String(),
		Body:      chirp.Body,
		UserId:    chirp.UserID.String(),
		CreatedAt: chirp.CreatedAt.String(),
		UpdatedAt: chirp.UpdatedAt.String(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type responseBody struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	}
	params := &requestBody{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil || params.Email == "" {
		http.Error(w, "Invalid JSON or missing email", http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: sql.NullString{String: hashedPassword, Valid: true},
	})

	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		ID:          user.ID.String(),
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
		CreatedAt:   user.CreatedAt.String(),
		UpdatedAt:   user.UpdatedAt.String(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenStr, cfg.jwtSecret)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type responseBody struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	}

	type errorResponse struct {
		Error string `json:"error"`
	}

	params := &requestBody{}

	err = json.NewDecoder(r.Body).Decode(params)

	if err != nil || params.Email == "" || params.Password == "" {
		http.Error(w, "Invalid JSON or missing email/password", http.StatusBadRequest)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: sql.NullString{String: hashedPassword, Valid: true},
	})

	if err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		ID:          user.ID.String(),
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
		CreatedAt:   user.CreatedAt.String(),
		UpdatedAt:   user.UpdatedAt.String(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type responseBody struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	params := &requestBody{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil || params.Email == "" || params.Password == "" {
		http.Error(w, "Invalid JSON or missing email or password", http.StatusBadRequest)
		return
	}

	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)

	if err != nil || !user.HashedPassword.Valid {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}
	err = auth.CheckPasswordHash(params.Password, user.HashedPassword.String)
	if err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, 1*time.Hour)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
	}

	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})

	if err != nil {
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		ID:           user.ID.String(),
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed.Bool,
		CreatedAt:    user.CreatedAt.String(),
		UpdatedAt:    user.UpdatedAt.String(),
		Token:        token,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type responseBody struct {
		Token string `json:"token"`
	}

	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, 1*time.Hour)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		Token: accessToken,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "Failed to revoke token: "+err.Error(), http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) polkaWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	apiKey, err := auth.GetApiKey(r.Header)

	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if apiKey != cfg.polkaKey {
		http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
		return
	}

	type webhookRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	params := &webhookRequest{}
	err = json.NewDecoder(r.Body).Decode(params)
	if err != nil || params.Event == "" || params.Data.UserID == "" {
		http.Error(w, "Invalid JSON or missing event/user_id", http.StatusBadRequest)
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	_, err = cfg.dbQueries.GetUserByID(r.Context(), userID)

	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// upgrade the user to chirpy red
	err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), userID)

	if err != nil {
		http.Error(w, "Failed to upgrade user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
