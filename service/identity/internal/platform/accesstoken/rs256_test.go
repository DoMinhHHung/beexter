package accesstoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://identity.beexster.test"
	testAudience = "beexster-api"
	testKeyID    = "identity-signing-2026-07"
	testSubject  = identity.ID("0198f124-659f-7cbd-a441-dc7eea175073")
	testDeviceID = "0198f124-659f-7cbd-a441-dc7eea175074"
	testJTI      = "0198f124-659f-7cbd-a441-dc7eea175075"
)

var (
	testKeysOnce sync.Once
	testKey      *rsa.PrivateKey
	testWrongKey *rsa.PrivateKey
	testOldKey   *rsa.PrivateKey
	testKeysErr  error
	tokenTestNow = time.Date(2026, time.July, 30, 12, 0, 0, 987654321, time.UTC)
)

func TestRS256IssueAndVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role identity.PlatformRole
	}{
		{name: "ordinary", role: identity.PlatformRoleNone},
		{name: "admin", role: identity.PlatformRoleAdmin},
		{name: "vice admin", role: identity.PlatformRoleViceAdmin},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			service := newTestService(t)
			input := validClaims(test.role)

			rawToken, expiresAt, err := service.Issue(input)
			if err != nil {
				t.Fatalf("issue token: %v", err)
			}

			wantIssuedAt := tokenTestNow.UTC().Truncate(time.Second)
			wantExpiresAt := wantIssuedAt.Add(DefaultAccessTokenTTL)
			if !expiresAt.Equal(wantExpiresAt) {
				t.Fatalf("expiration = %s, want %s", expiresAt, wantExpiresAt)
			}

			verified, err := service.Verify(rawToken, tokenTestNow)
			if err != nil {
				t.Fatalf("verify token: %v", err)
			}

			want := appauth.VerifiedAccessToken{
				Subject:      testSubject,
				DeviceID:     testDeviceID,
				PlatformRole: test.role,
				IssuedAt:     wantIssuedAt,
				ExpiresAt:    wantExpiresAt,
				JTI:          testJTI,
			}
			if !reflect.DeepEqual(verified, want) {
				t.Fatalf("verified claims = %+v, want %+v", verified, want)
			}
		})
	}
}

func TestRS256VerifiesTokenSignedBySupplementalPublicKey(t *testing.T) {
	t.Parallel()

	activePrivateKey, _ := testRSAKeys(t)
	oldPrivateKey := testOldRSAKey(t)

	activeConfig := validConfig()
	activeConfig.VerificationKeys = []VerificationKey{{
		KeyID:     "identity-signing-2026-06",
		PublicKey: &oldPrivateKey.PublicKey,
	}}
	activeService, err := New(activePrivateKey, activeConfig)
	if err != nil {
		t.Fatalf("create active service: %v", err)
	}

	oldConfig := validConfig()
	oldConfig.KeyID = "identity-signing-2026-06"
	oldService, err := New(oldPrivateKey, oldConfig)
	if err != nil {
		t.Fatalf("create old service: %v", err)
	}
	oldToken, _, err := oldService.Issue(validClaims(identity.PlatformRoleNone))
	if err != nil {
		t.Fatalf("issue old token: %v", err)
	}

	verified, err := activeService.Verify(oldToken, tokenTestNow)
	if err != nil {
		t.Fatalf("verify old token: %v", err)
	}
	if verified.Subject != testSubject || verified.JTI != testJTI {
		t.Fatalf("unexpected verified old token: %+v", verified)
	}

	newToken, _, err := activeService.Issue(validClaims(identity.PlatformRoleNone))
	if err != nil {
		t.Fatalf("issue active token: %v", err)
	}
	newHeader := decodeSegmentMap(t, strings.Split(newToken, ".")[0])
	if newHeader["kid"] != testKeyID {
		t.Fatalf("new token kid = %#v, want %q", newHeader["kid"], testKeyID)
	}
	if _, err := activeService.Verify(newToken, tokenTestNow); err != nil {
		t.Fatalf("active public key did not verify new token: %v", err)
	}
}

func TestRS256CopiesSupplementalPublicKeys(t *testing.T) {
	t.Parallel()

	activePrivateKey, _ := testRSAKeys(t)
	oldPrivateKey := testOldRSAKey(t)
	oldToken := signRS256(
		t,
		oldPrivateKey,
		"old-key",
		validWireClaims(identity.PlatformRoleNone),
	)
	configuredPublicKey := &rsa.PublicKey{
		N: new(big.Int).Set(oldPrivateKey.PublicKey.N),
		E: oldPrivateKey.PublicKey.E,
	}
	config := validConfig()
	config.VerificationKeys = []VerificationKey{{
		KeyID:     "old-key",
		PublicKey: configuredPublicKey,
	}}
	service, err := New(activePrivateKey, config)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	configuredPublicKey.N.SetInt64(3)
	configuredPublicKey.E = 3
	if _, err := service.Verify(oldToken, tokenTestNow); err != nil {
		t.Fatalf("caller mutation changed cached verification key: %v", err)
	}
}

func TestRS256IssuedTokenContract(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	rawToken, _, err := service.Issue(validClaims(identity.PlatformRoleNone))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}

	header := decodeSegmentMap(t, parts[0])
	wantHeader := map[string]any{
		"alg": AlgorithmRS256,
		"typ": JWTType,
		"kid": testKeyID,
	}
	if !reflect.DeepEqual(header, wantHeader) {
		t.Fatalf("header = %#v, want %#v", header, wantHeader)
	}

	claims := decodeSegmentMap(t, parts[1])
	for _, required := range []string{
		"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "device_id",
	} {
		if _, ok := claims[required]; !ok {
			t.Errorf("required claim %q is absent", required)
		}
	}
	for _, forbidden := range []string{
		"platform_role", "role", "email", "email_verified", "status",
	} {
		if _, ok := claims[forbidden]; ok {
			t.Errorf("ordinary token contains forbidden claim %q", forbidden)
		}
	}

	if claims["iss"] != testIssuer || claims["sub"] != testSubject.String() ||
		claims["jti"] != testJTI || claims["device_id"] != testDeviceID {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if !reflect.DeepEqual(claims["aud"], []any{testAudience}) {
		t.Fatalf("aud = %#v, want [%q]", claims["aud"], testAudience)
	}
	issuedAt := float64(tokenTestNow.UTC().Truncate(time.Second).Unix())
	if claims["iat"] != issuedAt || claims["nbf"] != issuedAt ||
		claims["exp"] != issuedAt+DefaultAccessTokenTTL.Seconds() {
		t.Fatalf("unexpected temporal claims: %#v", claims)
	}
}

func TestRS256IssuedPrivilegedTokenContainsPlatformRole(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	rawToken, _, err := service.Issue(validClaims(identity.PlatformRoleAdmin))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	parts := strings.Split(rawToken, ".")
	claims := decodeSegmentMap(t, parts[1])
	if claims["platform_role"] != string(identity.PlatformRoleAdmin) {
		t.Fatalf("platform_role = %#v", claims["platform_role"])
	}
}

func TestRS256RejectsHeaderAndTrustMismatches(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)

	tests := []struct {
		name  string
		issue func(*testing.T) string
	}{
		{
			name: "issuer mismatch",
			issue: func(t *testing.T) string {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.Issuer = "https://other-issuer.test"
				return signRS256(t, privateKey, testKeyID, claims)
			},
		},
		{
			name: "audience mismatch",
			issue: func(t *testing.T) string {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.Audience = jwt.ClaimStrings{"other-api"}
				return signRS256(t, privateKey, testKeyID, claims)
			},
		},
		{
			name: "kid mismatch",
			issue: func(t *testing.T) string {
				return signRS256(
					t,
					privateKey,
					"other-key",
					validWireClaims(identity.PlatformRoleNone),
				)
			},
		},
		{
			name: "missing kid",
			issue: func(t *testing.T) string {
				token := jwt.NewWithClaims(
					jwt.SigningMethodRS256,
					validWireClaims(identity.PlatformRoleNone),
				)
				return mustSign(t, token, privateKey)
			},
		},
		{
			name: "blank kid",
			issue: func(t *testing.T) string {
				token := jwt.NewWithClaims(
					jwt.SigningMethodRS256,
					validWireClaims(identity.PlatformRoleNone),
				)
				token.Header["kid"] = " \t "
				return mustSign(t, token, privateKey)
			},
		},
		{
			name: "non-string kid",
			issue: func(t *testing.T) string {
				token := jwt.NewWithClaims(
					jwt.SigningMethodRS256,
					validWireClaims(identity.PlatformRoleNone),
				)
				token.Header["kid"] = 42
				return mustSign(t, token, privateKey)
			},
		},
		{
			name: "wrong typ",
			issue: func(t *testing.T) string {
				token := jwt.NewWithClaims(
					jwt.SigningMethodRS256,
					validWireClaims(identity.PlatformRoleNone),
				)
				token.Header["typ"] = "at+jwt"
				token.Header["kid"] = testKeyID
				return mustSign(t, token, privateKey)
			},
		},
		{
			name: "missing typ",
			issue: func(t *testing.T) string {
				token := jwt.NewWithClaims(
					jwt.SigningMethodRS256,
					validWireClaims(identity.PlatformRoleNone),
				)
				delete(token.Header, "typ")
				token.Header["kid"] = testKeyID
				return mustSign(t, token, privateKey)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := service.Verify(test.issue(t), tokenTestNow)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("error = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestRS256RejectsAlgorithmConfusionAndWrongSignature(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, wrongKey := testRSAKeys(t)
	claims := validWireClaims(identity.PlatformRoleNone)

	hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hsToken.Header["kid"] = testKeyID
	hsRaw := mustSign(t, hsToken, []byte("not-an-rsa-key"))

	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	noneToken.Header["kid"] = testKeyID
	noneRaw := mustSign(t, noneToken, jwt.UnsafeAllowNoneSignatureType)

	wrongSignature := signRS256(t, wrongKey, testKeyID, claims)
	validSignature := signRS256(t, privateKey, testKeyID, claims)
	parts := strings.Split(validSignature, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"tampered"}`))
	tamperedPayload := strings.Join(parts, ".")

	for name, rawToken := range map[string]string{
		"HS256":            hsRaw,
		"none":             noneRaw,
		"wrong RSA key":    wrongSignature,
		"tampered payload": tamperedPayload,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := service.Verify(rawToken, tokenTestNow)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("error = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestRS256RejectsInvalidTemporalClaims(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)
	secondNow := tokenTestNow.Truncate(time.Second)

	tests := []struct {
		name      string
		claims    tokenClaims
		verifyAt  time.Time
		wantError error
	}{
		{
			name:      "expired beyond skew",
			claims:    validWireClaims(identity.PlatformRoleNone),
			verifyAt:  secondNow.Add(DefaultAccessTokenTTL + DefaultAllowedClockSkew),
			wantError: ErrTokenExpired,
		},
		{
			name: "future iat outside skew",
			claims: wireClaimsAt(
				secondNow.Add(DefaultAllowedClockSkew+time.Second),
				identity.PlatformRoleNone,
			),
			verifyAt:  secondNow,
			wantError: ErrTokenInvalid,
		},
		{
			name: "future nbf outside skew",
			claims: func() tokenClaims {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.NotBefore = newNumericDate(
					secondNow.Add(DefaultAllowedClockSkew + time.Second),
				)
				return claims
			}(),
			verifyAt:  secondNow,
			wantError: ErrTokenInvalid,
		},
		{
			name: "nbf differs from iat",
			claims: func() tokenClaims {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.NotBefore = newNumericDate(secondNow.Add(time.Second))
				return claims
			}(),
			verifyAt:  secondNow,
			wantError: ErrTokenInvalid,
		},
		{
			name: "expiration does not equal configured TTL",
			claims: func() tokenClaims {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.ExpiresAt = newNumericDate(
					secondNow.Add(DefaultAccessTokenTTL + time.Second),
				)
				return claims
			}(),
			verifyAt:  secondNow,
			wantError: ErrTokenInvalid,
		},
		{
			name: "expired plus invalid issuer remains invalid",
			claims: func() tokenClaims {
				claims := validWireClaims(identity.PlatformRoleNone)
				claims.Issuer = "wrong"
				return claims
			}(),
			verifyAt: secondNow.Add(
				DefaultAccessTokenTTL + DefaultAllowedClockSkew,
			),
			wantError: ErrTokenInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rawToken := signRS256(t, privateKey, testKeyID, test.claims)
			_, err := service.Verify(rawToken, test.verifyAt)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestRS256AllowsConfiguredClockSkew(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)
	secondNow := tokenTestNow.Truncate(time.Second)

	futureClaims := wireClaimsAt(
		secondNow.Add(DefaultAllowedClockSkew),
		identity.PlatformRoleNone,
	)
	if _, err := service.Verify(
		signRS256(t, privateKey, testKeyID, futureClaims),
		secondNow,
	); err != nil {
		t.Fatalf("verify at positive clock-skew boundary: %v", err)
	}

	ordinaryClaims := validWireClaims(identity.PlatformRoleNone)
	if _, err := service.Verify(
		signRS256(t, privateKey, testKeyID, ordinaryClaims),
		secondNow.Add(DefaultAccessTokenTTL+DefaultAllowedClockSkew-time.Second),
	); err != nil {
		t.Fatalf("verify inside expiration clock skew: %v", err)
	}
}

func TestRS256PreservesValidSubSecondTTL(t *testing.T) {
	t.Parallel()

	privateKey, _ := testRSAKeys(t)
	config := validConfig()
	config.AccessTokenTTL = 1500 * time.Millisecond
	config.AllowedClockSkew = 250 * time.Millisecond
	service, err := New(privateKey, config)
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}

	rawToken, expiresAt, err := service.Issue(
		validClaims(identity.PlatformRoleNone),
	)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	wantExpiresAt := tokenTestNow.Truncate(time.Second).Add(1500 * time.Millisecond)
	if !expiresAt.Equal(wantExpiresAt) {
		t.Fatalf("expiration = %s, want %s", expiresAt, wantExpiresAt)
	}
	verified, err := service.Verify(rawToken, tokenTestNow)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if !verified.ExpiresAt.Equal(wantExpiresAt) {
		t.Fatalf("verified expiration = %s, want %s", verified.ExpiresAt, wantExpiresAt)
	}

	parts := strings.Split(rawToken, ".")
	wire := decodeSegmentMap(t, parts[1])
	if wire["iat"] != float64(tokenTestNow.Truncate(time.Second).Unix()) ||
		wire["exp"] != float64(tokenTestNow.Truncate(time.Second).Unix())+1.5 {
		t.Fatalf("unexpected sub-second temporal claims: %#v", wire)
	}
}

func TestRS256RejectsMissingRequiredClaims(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)

	tests := []struct {
		name   string
		mutate func(*tokenClaims)
	}{
		{name: "issuer", mutate: func(c *tokenClaims) { c.Issuer = "" }},
		{name: "audience", mutate: func(c *tokenClaims) { c.Audience = nil }},
		{name: "subject", mutate: func(c *tokenClaims) { c.Subject = "" }},
		{name: "expiration", mutate: func(c *tokenClaims) { c.ExpiresAt = nil }},
		{name: "issued at", mutate: func(c *tokenClaims) { c.IssuedAt = nil }},
		{name: "not before", mutate: func(c *tokenClaims) { c.NotBefore = nil }},
		{name: "JTI", mutate: func(c *tokenClaims) { c.ID = "" }},
		{name: "device ID", mutate: func(c *tokenClaims) { c.DeviceID = "" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := validWireClaims(identity.PlatformRoleNone)
			test.mutate(&claims)
			_, err := service.Verify(
				signRS256(t, privateKey, testKeyID, claims),
				tokenTestNow,
			)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("error = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestRS256RejectsInvalidUUIDsAndPlatformRoles(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)

	tests := []struct {
		name   string
		mutate func(*tokenClaims)
	}{
		{
			name:   "subject is not UUID",
			mutate: func(c *tokenClaims) { c.Subject = "not-a-uuid" },
		},
		{
			name: "subject is UUIDv4",
			mutate: func(c *tokenClaims) {
				c.Subject = "7b9c7f9a-4ea1-4d24-a573-6915ea8c3933"
			},
		},
		{
			name:   "device ID is invalid",
			mutate: func(c *tokenClaims) { c.DeviceID = "not-a-uuid" },
		},
		{
			name: "device ID is UUIDv4",
			mutate: func(c *tokenClaims) {
				c.DeviceID = "7b9c7f9a-4ea1-4d24-a573-6915ea8c3933"
			},
		},
		{
			name:   "JTI is invalid",
			mutate: func(c *tokenClaims) { c.ID = "not-a-uuid" },
		},
		{
			name: "JTI is UUIDv4",
			mutate: func(c *tokenClaims) {
				c.ID = "7b9c7f9a-4ea1-4d24-a573-6915ea8c3933"
			},
		},
		{
			name: "unknown platform role",
			mutate: func(c *tokenClaims) {
				role := identity.PlatformRole("SUPER_ADMIN")
				c.PlatformRole = &role
			},
		},
		{
			name: "lowercase platform role",
			mutate: func(c *tokenClaims) {
				role := identity.PlatformRole("admin")
				c.PlatformRole = &role
			},
		},
		{
			name: "explicit empty platform role",
			mutate: func(c *tokenClaims) {
				role := identity.PlatformRoleNone
				c.PlatformRole = &role
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := validWireClaims(identity.PlatformRoleNone)
			test.mutate(&claims)
			_, err := service.Verify(
				signRS256(t, privateKey, testKeyID, claims),
				tokenTestNow,
			)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("error = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestRS256RejectsExplicitNullPlatformRole(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)
	claimsJSON, err := json.Marshal(validWireClaims(identity.PlatformRoleNone))
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	claims["platform_role"] = nil
	claimsJSON, err = json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal explicit-null claims: %v", err)
	}

	_, err = service.Verify(
		signRawPayload(t, privateKey, claimsJSON),
		tokenTestNow,
	)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("error = %v, want ErrTokenInvalid", err)
	}
}

func TestRS256RejectsMalformedAndExtraJSONValuesWithoutPanic(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	privateKey, _ := testRSAKeys(t)
	validClaimsJSON, err := json.Marshal(validWireClaims(identity.PlatformRoleNone))
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	extraJSON := signRawPayload(t, privateKey, append(validClaimsJSON, []byte(` {}`)...))

	inputs := []string{
		"",
		"not-a-token",
		"a.b.c",
		"a.b.c.d",
		"..",
		"eyJhbGciOiJSUzI1NiJ9.e30.",
		extraJSON,
		strings.Repeat("x", 4096),
	}
	for _, rawToken := range inputs {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Verify(%q) panicked: %v", rawToken, recovered)
				}
			}()

			_, verifyErr := service.Verify(rawToken, tokenTestNow)
			if !errors.Is(verifyErr, ErrTokenInvalid) {
				t.Fatalf("Verify(%q) error = %v", rawToken, verifyErr)
			}
		}()
	}
}

func TestRS256IssueRejectsInvalidClaims(t *testing.T) {
	t.Parallel()

	service := newTestService(t)
	tests := []struct {
		name   string
		mutate func(*appauth.AccessTokenClaims)
	}{
		{name: "zero subject", mutate: func(c *appauth.AccessTokenClaims) { c.Subject = "" }},
		{
			name: "invalid subject",
			mutate: func(c *appauth.AccessTokenClaims) {
				c.Subject = identity.ID("7b9c7f9a-4ea1-4d24-a573-6915ea8c3933")
			},
		},
		{name: "device ID", mutate: func(c *appauth.AccessTokenClaims) { c.DeviceID = "bad" }},
		{name: "JTI", mutate: func(c *appauth.AccessTokenClaims) { c.JTI = "bad" }},
		{name: "issued at", mutate: func(c *appauth.AccessTokenClaims) { c.IssuedAt = time.Time{} }},
		{
			name: "platform role",
			mutate: func(c *appauth.AccessTokenClaims) {
				c.PlatformRole = identity.PlatformRole("AGENCY")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(identity.PlatformRoleNone)
			test.mutate(&claims)
			_, _, err := service.Issue(claims)
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("error = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestRS256RejectsUninitializedUse(t *testing.T) {
	t.Parallel()

	var service *RS256
	if _, _, err := service.Issue(validClaims(identity.PlatformRoleNone)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Issue error = %v", err)
	}
	if _, err := service.Verify("anything", tokenTestNow); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Verify error = %v", err)
	}
}

func newTestService(t *testing.T) *RS256 {
	t.Helper()
	privateKey, _ := testRSAKeys(t)
	service, err := New(privateKey, validConfig())
	if err != nil {
		t.Fatalf("create token service: %v", err)
	}
	return service
}

func validConfig() Config {
	return Config{
		Issuer:           testIssuer,
		Audience:         testAudience,
		KeyID:            testKeyID,
		AccessTokenTTL:   DefaultAccessTokenTTL,
		AllowedClockSkew: DefaultAllowedClockSkew,
	}
}

func validClaims(role identity.PlatformRole) appauth.AccessTokenClaims {
	return appauth.AccessTokenClaims{
		Subject:      testSubject,
		DeviceID:     testDeviceID,
		PlatformRole: role,
		IssuedAt:     tokenTestNow,
		JTI:          testJTI,
	}
}

func validWireClaims(role identity.PlatformRole) tokenClaims {
	return wireClaimsAt(tokenTestNow.Truncate(time.Second), role)
}

func wireClaimsAt(issuedAt time.Time, role identity.PlatformRole) tokenClaims {
	var rolePointer *identity.PlatformRole
	if role.IsAssigned() {
		roleCopy := role
		rolePointer = &roleCopy
	}
	return tokenClaims{
		DeviceID:     testDeviceID,
		PlatformRole: rolePointer,
		Issuer:       testIssuer,
		Subject:      testSubject.String(),
		Audience:     jwt.ClaimStrings{testAudience},
		ExpiresAt:    newNumericDate(issuedAt.Add(DefaultAccessTokenTTL)),
		NotBefore:    newNumericDate(issuedAt),
		IssuedAt:     newNumericDate(issuedAt),
		ID:           testJTI,
	}
}

func signRS256(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	keyID string,
	claims tokenClaims,
) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	return mustSign(t, token, privateKey)
}

func mustSign(t *testing.T, token *jwt.Token, key any) string {
	t.Helper()
	rawToken, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return rawToken
}

func signRawPayload(t *testing.T, privateKey *rsa.PrivateKey, payload []byte) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": AlgorithmRS256,
		"typ": JWTType,
		"kid": testKeyID,
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerSegment + "." + payloadSegment
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		t.Fatalf("sign raw payload: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func decodeSegmentMap(t *testing.T, segment string) map[string]any {
	t.Helper()
	encoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode token segment: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("decode token JSON: %v", err)
	}
	return value
}

func testRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	testKeysOnce.Do(func() {
		testKey, testKeysErr = rsa.GenerateKey(rand.Reader, minimumRSAKeyBits)
		if testKeysErr != nil {
			return
		}
		testWrongKey, testKeysErr = rsa.GenerateKey(rand.Reader, minimumRSAKeyBits)
		if testKeysErr != nil {
			return
		}
		testOldKey, testKeysErr = rsa.GenerateKey(rand.Reader, minimumRSAKeyBits)
	})
	if testKeysErr != nil {
		t.Fatalf("generate test RSA keys: %v", testKeysErr)
	}
	return testKey, testWrongKey
}

func testOldRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAKeys(t)
	return testOldKey
}
