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
			if input.ActorID != actorID ||
				input.ActorPlatformRole != identity.PlatformRoleAdmin {
				t.Fatalf("unexpected actor: %+v", input)
			}
			if input.Email != "ViceAdmin@Example.COM" ||
				input.Password != "Secure1!" ||
				input.PlatformRole != "VICE_ADMIN" ||
				input.Locale != "ja" {
				t.Fatalf("unexpected input: %+v", input)
			}

			return appcreateidentity.Output{
				ID:           createdID,
				Email:        "viceadmin@example.com",
				PlatformRole: identity.PlatformRoleViceAdmin,
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
					UserID:       actorID,
					PlatformRole: identity.PlatformRoleAdmin,
				},
			)
			createPrivilegedIdentityHandler(testLogger(), executor).
				ServeHTTP(w, r.WithContext(ctx))
		}),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/admin/identities",
		strings.NewReader(`{"email":"ViceAdmin@Example.COM","password":"Secure1!","platform_role":"VICE_ADMIN"}`),
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

	responseBody := response.Body.Bytes()
	var payload createPrivilegedIdentityResponse
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.Data.ID != createdID.String() ||
		payload.Data.Email != "viceadmin@example.com" ||
		payload.Data.PlatformRole != string(identity.PlatformRoleViceAdmin) {
		t.Fatalf("unexpected response: %+v", payload)
	}

	var rawPayload map[string]map[string]any
	if err := json.Unmarshal(responseBody, &rawPayload); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	if _, exists := rawPayload["data"]["role"]; exists {
		t.Fatal("privileged identity response must not contain legacy role")
	}
}

func TestCreatePrivilegedIdentityHandlerRejectsLegacyRole(t *testing.T) {
	t.Parallel()

	actorID := identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	handler := applyMiddleware(
		testLogger(),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				authenticatedPrincipalContextKey{},
				appauth.Principal{
					UserID:       actorID,
					PlatformRole: identity.PlatformRoleAdmin,
				},
			)
			createPrivilegedIdentityHandler(
				testLogger(),
				&stubCreatePrivilegedIdentityExecutor{
					execute: func(
						context.Context,
						appcreateidentity.Input,
					) (appcreateidentity.Output, error) {
						t.Fatal("executor must not be called")
						return appcreateidentity.Output{}, nil
					},
				},
			).ServeHTTP(w, r.WithContext(ctx))
		}),
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/admin/identities",
		strings.NewReader(
			`{"email":"viceadmin@example.com","password":"Secure1!","role":"VICE_ADMIN"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusBadRequest,
			response.Code,
			response.Body.String(),
		)
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
