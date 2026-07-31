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
	} {
		if !bytes.Contains(openAPISpec, route) {
			t.Fatalf("OpenAPI spec missing %q", route)
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
