package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appauth "github.com/DoMinhHHung/beexter/service/identity/internal/application/auth"
	appcreateidentity "github.com/DoMinhHHung/beexter/service/identity/internal/application/createidentity"
	"github.com/DoMinhHHung/beexter/service/identity/internal/domain/identity"
)

func TestCreatePrivilegedIdentityHandler(t *testing.T) {
	t.Parallel()

	actorID := identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	createdID := identity.ID("0198f124-659f-7cbd-a441-dc7eea175074")

	executor := &stubCreatePrivilegedIdentityExecutor{
		execute: func(
			_ context.Context,
			input appcreateidentity.Input,
		) (appcreateidentity.Output, error) {
			if input.ActorID != actorID || input.ActorRole != identity.RoleAdmin {
				t.Fatalf("unexpected actor: %+v", input)
			}
			if input.Email != "Agency@Example.COM" ||
				input.Password != "Secure1!" ||
				input.Role != "AGENCY" ||
				input.Locale != "ja" {
				t.Fatalf("unexpected input: %+v", input)
			}

			return appcreateidentity.Output{
				ID:    createdID,
				Email: "agency@example.com",
				Role:  identity.RoleAgency,
			}, nil
		},
	}

	handler := applyMiddleware(
		testLogger(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				authenticatedPrincipalContextKey{},
				appauth.Principal{
					UserID: actorID,
					Role:   identity.RoleAdmin,
				},
			)
			createPrivilegedIdentityHandler(testLogger(), executor).
				ServeHTTP(w, r.WithContext(ctx))
		}),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/admin/identities",
		strings.NewReader(`{"email":"Agency@Example.COM","password":"Secure1!","role":"AGENCY"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Language", "ja-JP, en;q=0.8")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusCreated,
			response.Code,
			response.Body.String(),
		)
	}

	var payload createPrivilegedIdentityResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.ID != createdID.String() ||
		payload.Data.Email != "agency@example.com" ||
		payload.Data.Role != string(identity.RoleAgency) ||
		payload.Data.EmailVerified {
		t.Fatalf("unexpected response: %+v", payload)
	}
}

type stubCreatePrivilegedIdentityExecutor struct {
	execute func(
		context.Context,
		appcreateidentity.Input,
	) (appcreateidentity.Output, error)
}

func (s *stubCreatePrivilegedIdentityExecutor) Execute(
	ctx context.Context,
	input appcreateidentity.Input,
) (appcreateidentity.Output, error) {
	return s.execute(ctx, input)
}
