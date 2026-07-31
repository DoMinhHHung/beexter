package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	appchangepassword "github.com/DoMinhHHung/beexter/service/identity/internal/application/changepassword"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

const changePasswordHandlerUserID = identity.ID(
	"0198f124-659f-7cbd-a441-dc7eea175073",
)

func TestChangePasswordHandler(t *testing.T) {
	t.Parallel()

	executor := &stubChangePasswordExecutor{
		execute: func(
			_ context.Context,
			input appchangepassword.Input,
		) (appchangepassword.Output, error) {
			if input.UserID != changePasswordHandlerUserID {
				t.Fatalf("unexpected user ID %s", input.UserID)
			}
			if input.CurrentPassword != "Secure1!" ||
				input.NewPassword != "Secure2!" {
				t.Fatalf("unexpected password input")
			}
			if input.IPAddress.String() != "192.0.2.10" {
				t.Fatalf("unexpected IP %s", input.IPAddress)
			}
			if input.RequestID == "" {
				t.Fatal("expected request ID")
			}
			return appchangepassword.Output{PasswordChanged: true}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				authenticatedPrincipalContextKey{},
				appauth.Principal{
					UserID:       changePasswordHandlerUserID,
					DeviceID:     "0198f124-659f-7cbd-a441-dc7eea175074",
					PlatformRole: identity.PlatformRoleNone,
					IssuedAt:     time.Now().Add(-time.Minute),
					ExpiresAt:    time.Now().Add(time.Hour),
				},
			)
			changePasswordHandler(testLogger(), executor).ServeHTTP(
				w,
				r.WithContext(ctx),
			)
		}),
	)

	request := httptest.NewRequest(
		http.MethodPut,
		"/v1/auth/change-password",
		strings.NewReader(
			`{"current_password":"Secure1!","new_password":"Secure2!"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:54321"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	var payload changePasswordResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Data.PasswordChanged {
		t.Fatal("expected password_changed=true")
	}
}

type stubChangePasswordExecutor struct {
	execute func(
		context.Context,
		appchangepassword.Input,
	) (appchangepassword.Output, error)
}

func (s *stubChangePasswordExecutor) Execute(
	ctx context.Context,
	input appchangepassword.Input,
) (appchangepassword.Output, error) {
	return s.execute(ctx, input)
}
