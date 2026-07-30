package outbox

import (
	"encoding/json"
	"testing"
)

func TestDecodeVerificationPayloadNormalizesLocale(t *testing.T) {
	t.Parallel()

	rawPayload, err := json.Marshal(map[string]string{
		"identity_id": "0198f124-659f-7cbd-a441-dc7eea175073",
		"token_id":    "0198f124-659f-7cbd-a441-dc7eea175074",
		"locale":      "JA-jp",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	payload, err := decodeVerificationPayload(rawPayload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if payload.Locale != "ja" {
		t.Fatalf("expected locale ja, got %q", payload.Locale)
	}
}

func TestDecodeLegacyVerificationPayloadFallsBackToEnglish(
	t *testing.T,
) {
	t.Parallel()

	rawPayload := []byte(`{
        "identity_id":"0198f124-659f-7cbd-a441-dc7eea175073",
        "token_id":"0198f124-659f-7cbd-a441-dc7eea175074"
    }`)

	payload, err := decodeVerificationPayload(rawPayload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if payload.Locale != "en" {
		t.Fatalf("expected English fallback, got %q", payload.Locale)
	}
}
