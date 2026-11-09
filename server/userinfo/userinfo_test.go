package userinfo

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/storage/memory"
)

func TestUserInfoAcceptsSignerAlgorithm(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.RS256, jose.ES256} {
		t.Run(string(alg), func(t *testing.T) {
			ctx := t.Context()
			logger := slog.New(slog.DiscardHandler)

			localConfig := signer.LocalConfig{
				KeysRotationPeriod: time.Hour.String(),
				Algorithm:          alg,
			}
			sig, err := localConfig.Open(ctx, memory.New(logger), time.Hour, time.Now, logger)
			require.NoError(t, err)
			sig.Start(ctx)

			const issuer = "https://issuer.example.com"
			claims, err := json.Marshal(map[string]any{
				"iss": issuer,
				"sub": "jane",
				"aud": "client",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			require.NoError(t, err)
			token, err := sig.Sign(ctx, claims)
			require.NoError(t, err)

			handler := &Handler{Issuer: issuer, Signer: sig, Logger: logger}
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.handle(rec, req)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var got map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			require.Equal(t, "jane", got["sub"])
		})
	}
}
