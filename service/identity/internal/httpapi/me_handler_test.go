package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	getmeapp "github.com/DoMinhHHung/beexter/service/identity/internal/application/getme"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestMeHandlerReturnsBasicIdentity(t *testing.T) {
	t.Parallel()

	userID := identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	createdAt := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)

	executor := &stubGetMeExecutor{
		execute: func(
			_ context.Context,
			input getmeapp.Input,
		) (getmeapp.Output, error) {
			if input.UserID != userID {
				t.Fatalf("unexpected user ID %q", input.UserID)
			}
			return getmeapp.Output{
				ID:            userID,
				Email:         "user@example.com",
				Role:          identity.RoleJobSeeker,
				Status:        identity.StatusActive,
				EmailVerified: true,
				CreatedAt:     createdAt,
				UpdatedAt:     updatedAt,
			}, nil
		},
	}

	handler := withMePrincipal(
		appauth.Principal{UserID: userID},
		meHandler(testLogger(), executor),
	)

	request := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload meResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.ID != userID.String() ||
		payload.Data.Email != "user@example.com" ||
		payload.Data.Role != string(identity.RoleJobSeeker) ||
		payload.Data.Status != string(identity.StatusActive) ||
		!payload.Data.EmailVerified ||
		!payload.Data.CreatedAt.Equal(createdAt) ||
		!payload.Data.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("unexpected response: %+v", payload)
	}
}

func TestMeHandlerRequiresPrincipal(t *testing.T) {
	t.Parallel()

	handler := meHandler(
		testLogger(),
		&stubGetMeExecutor{execute: func(
			context.Context,
			getmeapp.Input,
		) (getmeapp.Output, error) {
			t.Fatal("executor must not be called")
			return getmeapp.Output{}, nil
		}},
	)

	request := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", response.Code)
	}
}

func withMePrincipal(
	principal appauth.Principal,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(
			r.Context(),
			authenticatedPrincipalContextKey{},
			principal,
		)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type stubGetMeExecutor struct {
	execute func(context.Context, getmeapp.Input) (getmeapp.Output, error)
}

func (s *stubGetMeExecutor) Execute(
	ctx context.Context,
	input getmeapp.Input,
) (getmeapp.Output, error) {
	return s.execute(ctx, input)
}
