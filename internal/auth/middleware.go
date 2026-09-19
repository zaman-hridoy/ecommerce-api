package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/zaman-hridoy/ecommerce-api/internal/httpx"
	"github.com/zaman-hridoy/ecommerce-api/internal/user"
)


func (s *Service) Middleware( next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractAccessToken(r)

		if token == "" {
			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				map[string]string{
					"error": "Unauthorized",
				},
			)

			return
		}

		tokenHash := HashToken(token)
		session, err := s.sessions.FindByAccessTokenHash(r.Context(), tokenHash)

		if err != nil {
				if errors.Is(err, ErrInvalidSession) {
					httpx.WriteJSON(
					w,
					http.StatusUnauthorized,
					map[string]string{
						"error": "Unauthorized",
					},
				)

				return
			}

			
			httpx.WriteJSON(
				w,
				http.StatusInternalServerError,
				map[string]string{
					"error": "internal server error",
				},
			)

			return
		}


		ctx := user.WithAuthContext(r.Context(), session.UserID, session.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}


func extractAccessToken(r *http.Request) string {
	//mobile/native client
	authorization := r.Header.Get("Authorization")

	if authorization != "" {
		const prefix = "Bearer "
		if strings.HasPrefix(authorization, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
		}
	}

	// production web Cookie
	cookie, err := r.Cookie("__Host-access")

	if err == nil {
		return cookie.Value
	}

	// local development cookie
	cookie, err = r.Cookie("access")
	if err == nil {
		return cookie.Value
	}

	return ""
}