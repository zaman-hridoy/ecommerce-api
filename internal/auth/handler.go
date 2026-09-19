package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/zaman-hridoy/ecommerce-api/internal/httpx"
	"github.com/zaman-hridoy/ecommerce-api/internal/user"
)


type Handler struct {
	service *Service
	logger *slog.Logger
	secureCookie bool
}


func NewHandler(service *Service, logger *slog.Logger, securecookie bool) *Handler {
	return &Handler{
		service: service,
		logger: logger,
		secureCookie: securecookie,
	}
}


const maxRegsiterBodySize = 1 << 20

/*
	1 << 20 = 1_048_576 bytes = 1 MiB
*/

type registerRequest struct {
	Name		string `json:"name"`
	Email		string `json:"email"`
	Password 	string `json:"password"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegsiterBodySize)
	defer r.Body.Close()

	var req registerRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid request body",
			},
		)
		return
	}

	createdUser, err := h.service.Register(
		r.Context(),
		RegisterInput{
			Name: req.Name,
			Email: req.Email,
			Password: req.Password,
		},
	)

	if err != nil {
		switch {
			case errors.Is(err, ErrNameRequired),
				errors.Is(err, ErrEmailRequired),
				errors.Is(err, ErrInvalidEmail),
				errors.Is(err, ErrPasswordRequired),
				errors.Is(err, ErrPasswordTooShort):

				httpx.WriteJSON(
					w,
					http.StatusBadRequest,
					map[string]string{
						"error": err.Error(),
					},
				)
				return

			case errors.Is(err, ErrEmailAlreadyExists):
				httpx.WriteJSON(
					w,
					http.StatusConflict,
					map[string]string{
						"error": err.Error(),
					},
				)

				return 

			default:
				h.logger.Error("register user failed", "error", err)
				httpx.WriteJSON(
					w,
					http.StatusInternalServerError,
					map[string]string{
						"error": err.Error(),
					},
				)
				return
		}
	}

	httpx.WriteJSON(
		w,
		http.StatusCreated,
		map[string]any{
			"success": true,
			"user": createdUser,
		},
	)
}

type loginRequest struct {
	Email		string `json:"email"`
	Password 	string `json:"password"`
	ClientType	string `json:"client_type"`
	DeviceName	string `json:"device_name"`
}

type loginResponse struct {
	User *user.User		`json:"user"`
	AccessToken string  `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType  string 	`json:"token_type,omitempty"`
	ExpiresIn  int64	`json:"expires_in"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegsiterBodySize)
	defer r.Body.Close()

	var req loginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid request body",
			},
		)
		return
	}

	if req.ClientType != "web" && req.ClientType != "mobile" {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error":"invalid client type",
			},
		)
		return
	}


	result, err := h.service.Login(r.Context(), LoginInput{
		Email: req.Email,
		Password: req.Password,
		DeviceType: req.ClientType,
		DeviceName: req.DeviceName,
	})

	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				map[string]string{
					"error": err.Error(),
				},
			)
			return
		}

		h.logger.Error("login failed", "error", err)
		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "internal server error",
			},
		)
		return
	}


	if req.ClientType == "web" {
		h.setWebAuthCookies(w, &RefreshResult{
			AccessToken: result.AccessToken,
			RefreshToken: result.RefreshToken,
			AccessExpiresAt: result.AccessExpiresAt,
			RefreshExpiresAt: result.RefreshExpiresAt,
		})
		httpx.WriteJSON(
			w,
			http.StatusOK,
			loginResponse{
				User: result.User,
				ExpiresIn: 900,
			},
		)

		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		loginResponse{
			User: result.User,
			AccessToken: result.AccessToken,
			RefreshToken: result.RefreshToken,
			TokenType: "Bearer",
			ExpiresIn: 900,
		},
	)
}

func (h *Handler) acccessCookieName() string {
	if h.secureCookie {
		return "__Host-access"
	}
	return "access"
}

func (h *Handler) refreshCookieName() string {
	if h.secureCookie {
		return "__Host-refresh"
	}
	return "refresh"
}

func (h *Handler) setWebAuthCookies(w http.ResponseWriter, result *RefreshResult) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:  h.acccessCookieName(),
			Value: result.AccessToken,
			Path: "/",
			HttpOnly: true,
			Secure: h.secureCookie,
			SameSite: http.SameSiteLaxMode,
			Expires: result.AccessExpiresAt,
			MaxAge: int(time.Until(result.AccessExpiresAt).Seconds()),
		},
	)

	http.SetCookie(
		w,
		&http.Cookie{
			Name: h.refreshCookieName(),
			Value: result.RefreshToken,
			Path: "/api/v1/auth/refresh",
			HttpOnly: true,
			Secure: h.secureCookie,
			SameSite: http.SameSiteLaxMode,
			Expires: result.RefreshExpiresAt,
			MaxAge: int(time.Until(result.RefreshExpiresAt).Seconds()),
		},
	)
}


type refreshRequest struct {
	ClientType		string `json:"client_type"`
	RefreshToken	string `json:"refresh_token"`
}

func (h *Handler) extractRefreshToken(
	r *http.Request,
	clientType string,
	bodyToken string,
) string {
	if clientType == "mobile" {
		return bodyToken
	}

	cookieName := h.refreshCookieName()
	cookie, err := r.Cookie(cookieName)

	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegsiterBodySize)

	defer r.Body.Close()
	var req refreshRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()


	

	if err := decoder.Decode(&req); err != nil {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid request body",
			},
		)
		return
	}


	if req.ClientType != "web" && req.ClientType != "mobile" {
		httpx.WriteJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid client type",
			},
		)
		return
	}

	// for _, c := range r.Cookies() {
	// 	fmt.Printf(
	// 		"cookie name=%s value=%s path=%s\n",
	// 		c.Name,
	// 		c.Value,
	// 		c.Path,
	// 	)
	// }

	refreshToken := h.extractRefreshToken(r, req.ClientType, req.RefreshToken)

	
	if refreshToken == "" {
		httpx.WriteJSON(
			w,
			http.StatusUnauthorized,
			map[string]string{
				"error": "invalid session",
			},
		)
		return
	}

	result, err := h.service.Refresh(r.Context(), RefreshInput{RefreshToken: refreshToken})

	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			httpx.WriteJSON(
				w,
				http.StatusUnauthorized,
				map[string]string{
					"error": "invalid session",
				},
			)

			return
		}

		h.logger.Error("refresh session failed", "error", err)
		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "internal server error",
			},
		)
		return
	}

	
	// response 
	if req.ClientType == "web" {
		h.setWebAuthCookies(w, result)
		httpx.WriteJSON(
			w,
			http.StatusOK,
			map[string]any{
				"expires_in": 900,
			},
		)

		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		map[string]any{
			"access_token": result.AccessToken,
			"refresh_token": result.RefreshToken,
			"token_type": "Bearer",
			"expires_in": 900,
		},
	)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID, ok := user.SessionIDFromContext(r.Context())
	if !ok {
		httpx.WriteJSON(
			w,
			http.StatusUnauthorized,
			map[string]string{
				"error": "Unauthorized",
			},
		)
		return
	}

	err := h.service.Logout(r.Context(), sessionID)

	if err != nil {
		h.logger.Error("logout failed", "error", err, "session_id", sessionID)
		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "internal server error",
			},
		)
		return
	}

	h.clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
} 

func (h *Handler) clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name: h.acccessCookieName(),
			Value: "",
			Path: "/",
			HttpOnly: true,
			Secure: h.secureCookie,
			SameSite: http.SameSiteLaxMode,
			MaxAge: -1,
		},
	)

	http.SetCookie(
		w,
		&http.Cookie{
			Name: h.refreshCookieName(),
			Value: "",
			Path: "/api/v1/auth/refresh",
			HttpOnly: true,
			Secure: h.secureCookie,
			SameSite: http.SameSiteStrictMode,
			MaxAge: -1,
		},
	)
}