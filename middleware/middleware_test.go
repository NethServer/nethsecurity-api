package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NethServer/nethsecurity-api/configuration"
	"github.com/NethServer/nethsecurity-api/logs"
)

// TestLogoutWithInvalidToken reproduces the panic that occurred when a stale
// browser called POST /logout with an expired/invalid JWT: the LogoutResponse
// callback did a nil interface{} -> string type assertion and panicked.
// The handler must not panic and must return 200.
func TestLogoutWithInvalidToken(t *testing.T) {
	logs.Init("test")
	os.Setenv("SECRET_JWT", "test-secret-logout")
	os.Setenv("SECRETS_DIR", "/tmp/secrets")
	os.Setenv("TOKENS_DIR", "/tmp/tokens")
	configuration.Init()

	jwtMiddleware = nil
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/logout", InstanceJWT().LogoutHandler)

	cases := map[string]string{
		"no token":      "",
		"garbage token": "Bearer not-a-real-jwt",
		"expired token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InJvb3QiLCJleHAiOjEwMDAwMDAwMH0.invalidsig",
	}

	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/logout", nil)
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			w := httptest.NewRecorder()

			// Before the fix this call panicked inside LogoutResponse.
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("logout with %s: got status %d, want 200", name, w.Code)
			}
		})
	}
}
