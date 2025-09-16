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

	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)

	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)

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

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type requestBody struct {
		Body   string `json:"body"`
		UserID string `json:"user_id"`
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
	params := &requestBody{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil || params.Body == "" || params.UserID == "" {
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
		UserID:    uuid.MustParse(params.UserID),
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
		ID        string `json:"id"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	params := &requestBody{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil || params.Email == "" {
		http.Error(w, "Invalid JSON or missing email", http.StatusBadRequest)
		return
	}

	hassedPassword, err := auth.HashPassword(params.Password)

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: sql.NullString{String: hassedPassword, Valid: true},
	})

	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	resp := responseBody{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.String(),
		UpdatedAt: user.UpdatedAt.String(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
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
		ID        string `json:"id"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
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

	resp := responseBody{
		ID:        user.ID.String(),
		Email:     user.Email,
		CreatedAt: user.CreatedAt.String(),
		UpdatedAt: user.UpdatedAt.String(),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

}
