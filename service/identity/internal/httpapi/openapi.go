package httpapi

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed openapi/openapi.yaml
var openAPISpec []byte

var swaggerPage = template.Must(template.New("swagger").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Beexter Identity API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function () {
      SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        displayRequestDuration: true,
        persistAuthorization: true
      });
    };
  </script>
</body>
</html>`))

func openAPIHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(openAPISpec); err != nil && logger != nil {
			logger.Warn("failed to write OpenAPI document", slog.String("error", err.Error()))
		}
	}
}

func swaggerUIHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'none'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'; img-src 'self' data:; font-src https://cdn.jsdelivr.net; frame-ancestors 'none'",
		)
		if err := swaggerPage.Execute(w, nil); err != nil && logger != nil {
			logger.Error("failed to render Swagger UI", slog.String("error", err.Error()))
		}
	}
}
