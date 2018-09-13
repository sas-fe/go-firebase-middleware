package fbauthmiddleware

import (
	"context"
	"net/http"

	"firebase.google.com/go/auth"
)

// FirebaseAuthMiddleware adds userID to request context
type FirebaseAuthMiddleware struct {
	Auth *auth.Client
}

// NewFirebaseAuthMiddleWare creates a new middleware instance
func NewFirebaseAuthMiddleWare(auth *auth.Client) *FirebaseAuthMiddleware {
	return &FirebaseAuthMiddleware{Auth: auth}
}

// Middleware checks for valid Firebase token and adds userID to context
func (m *FirebaseAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fbToken := r.Header.Get("Authorization")
		if fbToken == "" {
			http.Error(w, "missing auth token", http.StatusUnauthorized)
			return
		}

		token, err := m.Auth.VerifyIDToken(context.Background(), fbToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userID := token.UID

		newContext := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(newContext))
	})
}
