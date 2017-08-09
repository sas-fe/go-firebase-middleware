package firebaseAuthMiddleware

import (
	"context"
	"net/http"

	fbAdmin "github.com/acoshift/go-firebase-admin"
)

// FirebaseAuthMiddleware adds userID to request context
type FirebaseAuthMiddleware struct {
	Auth *fbAdmin.Auth
}

// NewFirebaseAuthMiddleWare creates a new middleware instance
func NewFirebaseAuthMiddleWare(auth *fbAdmin.Auth) *FirebaseAuthMiddleware {
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

		claims, err := m.Auth.VerifyIDToken(fbToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		userID := claims.UserID

		newContext := context.WithValue(r.Context(), "userID", userID)
		next.ServeHTTP(w, r.WithContext(newContext))
	})
}
