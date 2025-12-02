package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Apps []AppConfig `yaml:"apps"`
}

type AppConfig struct {
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description"`
	Env         []EnvDetails `yaml:"env"`
}

type EnvDetails map[string]Env

type Env struct {
	Groups   []string `yaml:"groups" json:"groups"`
	Emails   []string `yaml:"emails" json:"emails"`
	Upstream string   `yaml:"upstream" json:"upstream"`
}

// Extract custom claims.
var Claims struct {
	Email    string   `json:"email"`
	Verified bool     `json:"email_verified"`
	Groups   []string `json:"groups"`
	Name     string   `json:"name"`
}

type StateInfo struct {
	CodeVerifier string
	RedirectURL  string
}

var (
	issuer                 *string
	clientID               *string
	clientSecret           *string
	redirectURL            *string
	googleSAJSON           *string
	cookieDomain           *string
	googleImpersonateAdmin *string
	authHandlerPath        *string

	configData Config
	tpl        *template.Template
	oidcProv   *oidc.Provider
	oauth2Conf *oauth2.Config
	idVerifier *oidc.IDTokenVerifier
	stateStore = map[string]StateInfo{} // maps state -> codeVerifier & redirectURL
)

func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}
	if err := yaml.Unmarshal(data, &configData); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}
}

func generatePKCECodes() (state string, codeVerifier string, codeChallenge string, err error) {
	// Generate State
	b := make([]byte, 30)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", "", err
	}
	state = base64.RawURLEncoding.EncodeToString(b)

	// Generate a random code_verifier
	verifierBytes := make([]byte, 32) // 32 bytes for a 43-character verifier
	_, err = rand.Read(verifierBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate code_verifier: %w", err)
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code_challenge from code_verifier
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return state, codeVerifier, codeChallenge, nil
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// We expect user already logged in (session cookie) — else redirect to /login
	// In template, it will call JS fetch /api/apps which returns apps
	tpl.Execute(w, nil)
}

func apiAppsHandler(w http.ResponseWriter, r *http.Request) {
	// Expect user info in context
	rawClaims := r.Context().Value("claims")
	m, ok := rawClaims.(map[string]interface{})
	if !ok {
		http.Error(w, "invalid claims type", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(m)
	if err != nil {
		http.Error(w, "error marshalling claims", http.StatusInternalServerError)
		return
	}

	claims := Claims
	if err := json.Unmarshal(data, &claims); err != nil {
		http.Error(w, "error decoding claims", http.StatusInternalServerError)
		return
	}

	allowed := filterApps(claims.Groups, claims.Email)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allowed)
}

// filterApps same as before
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	m := map[string]struct{}{}
	for _, x := range a {
		m[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := m[y]; ok {
			return true
		}
	}
	return false
}

func filterApps(userGroups []string, userEmail string) []AppConfig {
	var allowedApps []AppConfig
	for _, app := range configData.Apps {
		for _, env := range app.Env {
			for envName, envDetails := range env {
				if contains(envDetails.Emails, userEmail) || intersects(envDetails.Groups, userGroups) {
					filteredEnv := EnvDetails{}
					filteredEnv[envName] = envDetails
					var allowedEnv []EnvDetails
					allowedEnv = append(allowedEnv, filteredEnv)
					allowedApp := AppConfig{
						Name:        app.Name,
						Description: app.Description,
						Env:         allowedEnv}
					allowedApps = append(allowedApps, allowedApp)
				}
			}
		}
	}

	return allowedApps
}

// login handler — starts the OAuth2 / OIDC authorization code flow
func loginHandler(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("rd")
	if redirectURL == "" {
		redirectURL = "/" // Default to the portal root if 'rd' is not present
	}

	// Generate state, codeVerifier, codeChallenge
	state, codeVerifier, codeChallenge, err := generatePKCECodes()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}

	// Store both the verifier AND the original redirect URL
	stateStore[state] = StateInfo{
		CodeVerifier: codeVerifier,
		RedirectURL:  redirectURL,
	}

	authCodeURL := oauth2Conf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// callback handler — Dex redirects here after login
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Validate state
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "state or code missing", http.StatusBadRequest)
		return
	}
	s, ok := stateStore[state]
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	delete(stateStore, state)

	// Exchange code for tokens
	token, err := oauth2Conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", s.CodeVerifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	// Verify ID token
	idToken, err := idVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		// HACK: if we failed token verification, it's possible the reason was because dex
		// restarted and has new JWKS signing keys (we do not back dex with persistent storage
		// so keys might be regenerated). Detect this by:
		// 1. looking for the specific error message
		// 2. re-initializing the OIDC provider
		// 3. re-attempting token verification
		// NOTE: the error message is sensitive to implementation of verifier.Verify()

		if !strings.Contains(err.Error(), "failed to verify id token signature") {
			http.Error(w, "invalid id token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("reinitialising OIDC Provider & Verifier...")
		oidcProv, _ = getOIDCProvider(*issuer)
		idVerifier = oidcProv.Verifier(&oidc.Config{ClientID: *clientID})
		idToken, err = idVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "invalid id token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// If we get here, we successfully re-initialized OIDC and after re-initialization,
		// the token is now valid.
		log.Println("New OIDC settings detected")
	}

	claims := &Claims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	groups, err := getUserGroups(context.Background(), claims.Email)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal error while fetching groups", http.StatusInternalServerError)
		return
	}
	claims.Groups = append(claims.Groups, groups...)

	ctx2 := context.WithValue(r.Context(), "claims", claims) // fix later

	// (Optional) Check email_verified
	if verified := claims.Verified; !verified {
		http.Error(w, "email not verified", http.StatusForbidden)
		return
	}

	cookie := &http.Cookie{
		Name:     "id_token",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   0,             // session cookie
		Domain:   *cookieDomain, // what URLs the cookies are sent to
	}

	http.SetCookie(w, cookie)

	// Redirect to index.html
	log.Printf("\nredirecting user %s to %s\n", claims.Email, s.RedirectURL)
	http.Redirect(w, r.WithContext(ctx2), s.RedirectURL, http.StatusFound)
}

func getUserGroups(ctx context.Context, userEmail string) ([]string, error) {
	saKeyJSON, err := os.ReadFile(*googleSAJSON)
	if err != nil {
		return nil, err
	}

	conf, err := google.JWTConfigFromJSON(saKeyJSON, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}
	conf.Subject = *googleImpersonateAdmin // must be a super admin

	srv, err := admin.NewService(ctx, option.WithTokenSource(conf.TokenSource(ctx)))
	if err != nil {
		return nil, err
	}
	groups, err := srv.Groups.List().UserKey(userEmail).Do()
	if err != nil {
		return nil, err
	}

	var result []string
	for _, g := range groups.Groups {
		result = append(result, g.Email)
	}
	return result, nil
}

// middleware to require login, parse cookie, verify token, attach claims
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// allow public paths
		if r.URL.Path == "/login" || r.URL.Path == "/callback" || r.URL.Path == *authHandlerPath || r.URL.Path == "/assets/portal-icon.png" {
			next.ServeHTTP(w, r)
			return
		}
		// read cookie
		c, err := r.Cookie("id_token")
		if err != nil {
			// not logged in → redirect to login
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		rawIDToken := c.Value
		// verify
		idTok, err := idVerifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			// invalid token → clear cookie & redirect to login
			http.SetCookie(w, &http.Cookie{
				Name:     "id_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		claims := map[string]interface{}{}
		if err := idTok.Claims(&claims); err != nil {
			http.Error(w, "cannot decode claims", http.StatusUnauthorized)
			return
		}

		groups, err := getUserGroups(context.Background(), claims["email"].(string))
		if err != nil {
			http.Error(w, "internal error while fetching groups", http.StatusInternalServerError)
			return
		}
		claims["groups"] = groups
		ctx2 := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx2))
	})
}

func getOIDCProvider(issuer string) (*oidc.Provider, error) {
	p, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		log.Fatalf("failed to get provider: %v", err)
	}
	return p, nil
}

func main() {
	issuer = flag.String("issuer", "http://localhost:5556/dex", "dex issuer url")
	clientID = flag.String("client-id", "portal-client", "dex client id")
	clientSecret = flag.String("client-secret", "JOdFlI3pQp50HaL5W057X+D3SNQ7PnrD0Kt7q5It6YGBYK0", "dex client secret")
	redirectURL = flag.String("callback-url", "http://localhost:8080/callback", "callback url")
	googleSAJSON = flag.String("google-sa-json", "google-sa.json", "google service account json")
	googleImpersonateAdmin = flag.String("google-impersonate-admin", "admin@example.id", "an admin user to impersonate")
	cookieDomain = flag.String("cookie-domain", "", "cookie domain")

	configPath := flag.String("config", "config.yaml", "app config")
	authHandlerPath = flag.String("auth-handler-path", "/ingress/auth", "custom path for nginx.ingress.kubernetes.io/auth-url")

	flag.Parse()

	loadConfig(*configPath)

	oidcProv, err := getOIDCProvider(*issuer)
	if err != nil {
		log.Fatal("failed to initialise OIDC provider with issuer : ", issuer)
	}
	idVerifier = oidcProv.Verifier(&oidc.Config{ClientID: *clientID})

	oauth2Conf = &oauth2.Config{
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Endpoint:     oidcProv.Endpoint(),
		RedirectURL:  *redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	// parse templates
	tpl = template.Must(template.ParseFiles("./templates/index.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/api/apps", apiAppsHandler)
	// The new endpoint for NGINX.
	mux.HandleFunc(*authHandlerPath, authHandler)

	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./templates/assets"))))

	handler := authMiddleware(mux)
	handler = loggingMiddleware(handler)

	log.Printf("Listening on :8080 ...")
	err = http.ListenAndServe(":8080", handler)
	if err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := "-"
		if c, err := r.Cookie("id_token"); err == nil {
			if idTok, err := idVerifier.Verify(r.Context(), c.Value); err == nil {
				claims := Claims
				_ = idTok.Claims(&claims)
				email = claims.Email
			}
		}
		log.Printf("%s %s from %s (user=%s)", r.Method, r.URL.Path, r.RemoteAddr, email)
		next.ServeHTTP(w, r)
	})
}

// Authorization Handler
func authHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the cookie from the request forwarded by NGINX after /login
	c, err := r.Cookie("id_token")
	if err != nil {
		// No cookie, user is not authenticated
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rawIDToken := c.Value

	idTok, err := idVerifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		// Invalid token
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims := Claims
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	// Determine which app is being accessed from headers set by NGINX
	targetHost, _ := url.Parse(r.Header.Get("X-Original-Url"))
	if targetHost.Host == "" {
		http.Error(w, "Missing X-Original-Url header", http.StatusBadRequest)
		return
	}

	// Check authorization for the target application
	var targetApp *AppConfig

	for i, app := range configData.Apps {
		for _, env := range app.Env {
			for _, envDetails := range env {
				host, _ := url.Parse(envDetails.Upstream)
				if host.Host == targetHost.Host {
					targetApp = &configData.Apps[i]
					break
				}
			}
			if targetApp != nil {
				break // stop checking other envs for this app
			}
		}
		if targetApp != nil {
			break // stop checking other apps
		}
	}

	if targetApp == nil {
		log.Printf("Authorization denied: No app config found for host %s", targetHost)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Fetch user's groups from Google
	userGroups, err := getUserGroups(r.Context(), claims.Email)
	if err != nil {
		log.Printf("ERROR fetching groups for %s: %v", claims.Email, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	claims.Groups = userGroups

	isAllowed := false
	for _, env := range targetApp.Env {
		for _, envDetails := range env {
			if contains(envDetails.Emails, claims.Email) || intersects(envDetails.Groups, userGroups) {
				isAllowed = true
				break
			}
		}
		if isAllowed {
			break
		}
	}

	if !isAllowed {
		log.Printf("Authorization denied for user %s to host %s", claims.Email, targetHost)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// If all checks pass, return 200 OK (nginx expects 200 OK only)
	log.Printf("Authorization success for user %s to host %s", claims.Email, targetHost)
	if err := setClaimInResponseHeaders(w, claims.Email, claims.Name, claims.Groups, rawIDToken); err != nil {
		log.Printf("error setting claim headers in the response")
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
}

func setClaimInResponseHeaders(w http.ResponseWriter, email string, name string, groups []string, jwtToken string) error {
	if email == "" || name == "" || len(groups) == 0 || jwtToken == "" {
		return errors.New("email or name or groups claim or jwtToken is empty")
	}

	// log.Printf("traits of user: %s, email: %s, groups:[%s]\n", name, email, groups) # for debug
	w.Header().Set("X-Portal-Claim-Email", email)
	w.Header().Set("X-Portal-Claim-Name", name)
	w.Header().Set("X-Portal-Claim-Groups", strings.Join(groups, ","))
	w.Header().Set("X-Portal-Jwt-Assertion", jwtToken)
	return nil
}
