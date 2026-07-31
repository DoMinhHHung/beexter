package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmbeddedOpenAPIDocumentsFinalSurface(t *testing.T) {
	t.Parallel()
	for _, route := range [][]byte{
		[]byte("/v1/auth/request-reactivation"),
		[]byte("/v1/me/login-history"),
		[]byte("delete:"),
		[]byte("/v1/admin/identities"),
		[]byte("/.well-known/jwks.json"),
		[]byte("PlatformRole:"),
		[]byte("platform_role:"),
		[]byte("enum: [VICE_ADMIN]"),
		[]byte("const: RS256"),
	} {
		if !bytes.Contains(openAPISpec, route) {
			t.Fatalf("OpenAPI spec missing %q", route)
		}
	}

	for _, legacy := range [][]byte{
		[]byte("\n    Role:"),
		[]byte("PublicRole:"),
		[]byte("PrivilegedCreatableRole:"),
		[]byte("\n        role:"),
		[]byte("CLIENT"),
		[]byte("JOB_SEEKER"),
		[]byte("AGENCY"),
	} {
		if bytes.Contains(openAPISpec, legacy) {
			t.Fatalf("OpenAPI spec contains legacy contract %q", legacy)
		}
	}

	response := httptest.NewRecorder()
	openAPIHandler(lifecycleTestLogger()).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil),
	)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") == "" {
		t.Fatalf("unexpected OpenAPI response: %d", response.Code)
	}
}
