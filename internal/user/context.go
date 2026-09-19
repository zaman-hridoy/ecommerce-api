package user

import "context"


type contextKey string

const (
	userIDContextKey contextKey = "user_id"
	sessionIDContextKey contextKey = "session_id"
)


func WithAuthContext(
	ctx context.Context,
	userID string,
	sessionID string,
) context.Context {
	ctx = context.WithValue(ctx, userIDContextKey, userID)
	ctx = context.WithValue(ctx, sessionIDContextKey, sessionID)
	return ctx
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	return userID, ok
}

func SessionIDFromContext(ctx context.Context) (string, bool) {
	sessionID, ok := ctx.Value(sessionIDContextKey).(string)
	return sessionID, ok
}