package user

import (
	"log/slog"
	"net/http"

	"github.com/zaman-hridoy/ecommerce-api/internal/httpx"
)


type Handler struct {
	repository *Repository
	logger *slog.Logger
}

func NewHandler(repo *Repository, logger *slog.Logger) *Handler {
	return &Handler{
		repository: repo,
		logger: logger,
	}
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())

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

	u, err := h.repository.FindByID(r.Context(), userID)
	if err != nil {
		h.logger.Error("get authenticated user failed", "error", err)

		httpx.WriteJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "internal server error",
			},
		)

		return
	}

	httpx.WriteJSON(
		w,
		http.StatusOK,
		map[string]any{
			"user": u,
		},
	)

}