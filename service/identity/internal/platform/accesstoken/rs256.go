package accesstoken

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	appauth "github.com/DoMinhHHung/beexster/service/identity/internal/application/auth"
	"github.com/DoMinhHHung/beexster/service/identity/internal/domain/identity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	DefaultAccessTokenTTL   = 15 * time.Minute
	MaximumAccessTokenTTL   = time.Hour
	DefaultAllowedClockSkew = 30 * time.Second
	MaximumAllowedClockSkew = 2 * time.Minute
)

var (
	ErrNotInitialized = errors.New("access-token service is not initialized")
	ErrConfigInvalid  = errors.New("access-token configuration is invalid")
	ErrTokenInvalid   = appauth.ErrAccessTokenInvalid
	ErrTokenExpired   = appauth.ErrAccessTokenExpired
)

type Config struct {
	Issuer           string
	Audience         string
	KeyID            string
	AccessTokenTTL   time.Duration
	AllowedClockSkew time.Duration
	VerificationKeys []VerificationKey
}

// VerificationKey is a verification-only RSA public key. It can represent a
// previous key retained during rotation or a next key pre-published before it
// becomes active. It can never be used by RS256.Issue.
type VerificationKey struct {
	KeyID     string
	PublicKey *rsa.PublicKey
}

type RS256 struct {
	privateKey       *rsa.PrivateKey
	verificationKeys map[string]*rsa.PublicKey
	issuer           string
	audience         string
	keyID            string
	accessTokenTTL   time.Duration
	allowedClockSkew time.Duration
	publicJWKS       []JWK
}

type tokenClaims struct {
	DeviceID            string                 `json:"device_id"`
	PlatformRole        *identity.PlatformRole `json:"platform_role,omitempty"`
	platformRolePresent bool
	Issuer              string           `json:"iss"`
	Subject             string           `json:"sub"`
	Audience            jwt.ClaimStrings `json:"aud"`
	ExpiresAt           *numericDate     `json:"exp"`
	NotBefore           *numericDate     `json:"nbf"`
	IssuedAt            *numericDate     `json:"iat"`
	ID                  string           `json:"jti"`
}

func (c *tokenClaims) UnmarshalJSON(encoded []byte) error {
	type claimsAlias tokenClaims
	var decoded claimsAlias
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return err
	}

	*c = tokenClaims(decoded)
	_, c.platformRolePresent = fields["platform_role"]
	return nil
}

func (c tokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwtNumericDate(c.ExpiresAt), nil
}

func (c tokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwtNumericDate(c.IssuedAt), nil
}

func (c tokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return jwtNumericDate(c.NotBefore), nil
}

func (c tokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c tokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c tokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// numericDate keeps issuance independent from jwt.TimePrecision. In
// particular, it preserves a valid sub-second configured TTL while iat and nbf
// remain integer-second values.
type numericDate struct {
	time.Time
	fractional bool
}

func newNumericDate(value time.Time) *numericDate {
	return &numericDate{Time: value.UTC()}
}

func (d numericDate) MarshalJSON() ([]byte, error) {
	seconds := strconv.FormatInt(d.Unix(), 10)
	if d.Nanosecond() == 0 {
		return []byte(seconds), nil
	}

	fraction := strings.TrimRight(
		fmt.Sprintf("%09d", d.Nanosecond()),
		"0",
	)
	return []byte(seconds + "." + fraction), nil
}

func (d *numericDate) UnmarshalJSON(encoded []byte) error {
	raw := string(encoded)
	whole, fraction, hasFraction := strings.Cut(raw, ".")
	if whole == "" || strings.HasPrefix(whole, "-") ||
		len(fraction) > 9 || hasFraction && fraction == "" {
		return errors.New("invalid numeric date")
	}

	seconds, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return errors.New("invalid numeric date")
	}

	var nanoseconds int64
	if hasFraction {
		for _, digit := range fraction {
			if digit < '0' || digit > '9' {
				return errors.New("invalid numeric date")
			}
		}
		padded := fraction + strings.Repeat("0", 9-len(fraction))
		nanoseconds, err = strconv.ParseInt(padded, 10, 64)
		if err != nil {
			return errors.New("invalid numeric date")
		}
	}

	d.Time = time.Unix(seconds, nanoseconds).UTC()
	d.fractional = hasFraction
	return nil
}

func jwtNumericDate(value *numericDate) *jwt.NumericDate {
	if value == nil {
		return nil
	}

	return &jwt.NumericDate{Time: value.Time}
}

func New(privateKey *rsa.PrivateKey, config Config) (*RS256, error) {
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, fmt.Errorf("create access-token service: %w", err)
	}

	issuer := strings.TrimSpace(config.Issuer)
	audience := strings.TrimSpace(config.Audience)
	keyID := strings.TrimSpace(config.KeyID)

	switch {
	case issuer == "":
		return nil, fmt.Errorf("%w: issuer is blank", ErrConfigInvalid)
	case audience == "":
		return nil, fmt.Errorf("%w: audience is blank", ErrConfigInvalid)
	case keyID == "":
		return nil, fmt.Errorf("%w: key ID is blank", ErrConfigInvalid)
	case config.AccessTokenTTL <= 0:
		return nil, fmt.Errorf(
			"%w: access-token TTL must be positive",
			ErrConfigInvalid,
		)
	case config.AccessTokenTTL > MaximumAccessTokenTTL:
		return nil, fmt.Errorf(
			"%w: access-token TTL exceeds %s",
			ErrConfigInvalid,
			MaximumAccessTokenTTL,
		)
	case config.AllowedClockSkew < 0:
		return nil, fmt.Errorf(
			"%w: allowed clock skew cannot be negative",
			ErrConfigInvalid,
		)
	case config.AllowedClockSkew > MaximumAllowedClockSkew:
		return nil, fmt.Errorf(
			"%w: allowed clock skew exceeds %s",
			ErrConfigInvalid,
			MaximumAllowedClockSkew,
		)
	}

	publicKey := copyPublicKey(&privateKey.PublicKey)
	verificationKeys := make(
		map[string]*rsa.PublicKey,
		len(config.VerificationKeys)+1,
	)
	verificationKeys[keyID] = publicKey

	additionalJWKs := make([]JWK, 0, len(config.VerificationKeys))
	for index, configuredKey := range config.VerificationKeys {
		configuredKeyID := strings.TrimSpace(configuredKey.KeyID)
		if configuredKeyID == "" {
			return nil, fmt.Errorf(
				"%w: verification key %d has a blank key ID",
				ErrConfigInvalid,
				index,
			)
		}
		if _, exists := verificationKeys[configuredKeyID]; exists {
			return nil, fmt.Errorf(
				"%w: verification key %d has a duplicate key ID",
				ErrConfigInvalid,
				index,
			)
		}
		if err := validatePublicKey(configuredKey.PublicKey); err != nil {
			return nil, fmt.Errorf(
				"create access-token service: verification key %d: %w",
				index,
				err,
			)
		}

		publicKeyCopy := copyPublicKey(configuredKey.PublicKey)
		verificationKeys[configuredKeyID] = publicKeyCopy
		additionalJWKs = append(
			additionalJWKs,
			newJWK(publicKeyCopy, configuredKeyID),
		)
	}
	sort.Slice(additionalJWKs, func(left, right int) bool {
		return additionalJWKs[left].KeyID < additionalJWKs[right].KeyID
	})

	publicJWKS := make([]JWK, 0, len(additionalJWKs)+1)
	publicJWKS = append(publicJWKS, newJWK(publicKey, keyID))
	publicJWKS = append(publicJWKS, additionalJWKs...)

	service := &RS256{
		privateKey:       privateKey,
		verificationKeys: verificationKeys,
		issuer:           issuer,
		audience:         audience,
		keyID:            keyID,
		accessTokenTTL:   config.AccessTokenTTL,
		allowedClockSkew: config.AllowedClockSkew,
		publicJWKS:       publicJWKS,
	}

	return service, nil
}

func copyPublicKey(publicKey *rsa.PublicKey) *rsa.PublicKey {
	return &rsa.PublicKey{
		N: new(big.Int).Set(publicKey.N),
		E: publicKey.E,
	}
}

func (s *RS256) Issue(
	claims appauth.AccessTokenClaims,
) (string, time.Time, error) {
	if !s.initialized() {
		return "", time.Time{}, ErrNotInitialized
	}

	if err := validateIssueClaims(claims); err != nil {
		return "", time.Time{}, err
	}

	issuedAt := claims.IssuedAt.UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(s.accessTokenTTL)

	var platformRole *identity.PlatformRole
	if claims.PlatformRole.IsAssigned() {
		role := claims.PlatformRole
		platformRole = &role
	}

	wireClaims := tokenClaims{
		DeviceID:     claims.DeviceID,
		PlatformRole: platformRole,
		Issuer:       s.issuer,
		Subject:      claims.Subject.String(),
		Audience:     jwt.ClaimStrings{s.audience},
		ExpiresAt:    newNumericDate(expiresAt),
		NotBefore:    newNumericDate(issuedAt),
		IssuedAt:     newNumericDate(issuedAt),
		ID:           claims.JTI,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, wireClaims)
	token.Header["kid"] = s.keyID

	rawToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}

	return rawToken, expiresAt, nil
}

func (s *RS256) Verify(
	rawToken string,
	now time.Time,
) (appauth.VerifiedAccessToken, error) {
	if !s.initialized() {
		return appauth.VerifiedAccessToken{}, ErrNotInitialized
	}
	if now.IsZero() || rawToken == "" {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}

	wireClaims := tokenClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{AlgorithmRS256}),
		jwt.WithStrictDecoding(),
		jwt.WithoutClaimsValidation(),
	)

	parsedToken, err := parser.ParseWithClaims(
		rawToken,
		&wireClaims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, ErrTokenInvalid
			}
			if token.Header["typ"] != JWTType {
				return nil, ErrTokenInvalid
			}
			keyID, ok := token.Header["kid"].(string)
			if !ok || strings.TrimSpace(keyID) == "" {
				return nil, ErrTokenInvalid
			}
			publicKey, exists := s.verificationKeys[keyID]
			if !exists || publicKey == nil {
				return nil, ErrTokenInvalid
			}

			return publicKey, nil
		},
	)
	if err != nil {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}
	if parsedToken == nil || !parsedToken.Valid {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}

	verified, err := s.validateVerifiedClaims(wireClaims, now.UTC())
	if err != nil {
		return appauth.VerifiedAccessToken{}, err
	}

	return verified, nil
}

func (s *RS256) initialized() bool {
	if s == nil || s.privateKey == nil || s.issuer == "" ||
		s.audience == "" || s.keyID == "" || s.accessTokenTTL <= 0 ||
		len(s.publicJWKS) == 0 {
		return false
	}

	publicKey, exists := s.verificationKeys[s.keyID]
	return exists && publicKey != nil
}

func validateIssueClaims(claims appauth.AccessTokenClaims) error {
	if claims.Subject.IsZero() || claims.IssuedAt.IsZero() ||
		claims.IssuedAt.Unix() <= 0 || !claims.PlatformRole.IsValidOrEmpty() {
		return ErrTokenInvalid
	}
	if _, err := identity.ParseID(claims.Subject.String()); err != nil {
		return ErrTokenInvalid
	}
	if err := validateCanonicalUUIDV7(claims.DeviceID); err != nil {
		return ErrTokenInvalid
	}
	if err := validateCanonicalUUIDV7(claims.JTI); err != nil {
		return ErrTokenInvalid
	}

	return nil
}

func (s *RS256) validateVerifiedClaims(
	claims tokenClaims,
	now time.Time,
) (appauth.VerifiedAccessToken, error) {
	if claims.ExpiresAt == nil || claims.IssuedAt == nil ||
		claims.NotBefore == nil || claims.Subject == "" ||
		claims.ID == "" || claims.DeviceID == "" ||
		claims.Issuer != s.issuer ||
		!slices.Contains(claims.Audience, s.audience) {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}

	issuedAt := claims.IssuedAt.Time.UTC()
	notBefore := claims.NotBefore.Time.UTC()
	expiresAt := claims.ExpiresAt.Time.UTC()
	if issuedAt.Unix() <= 0 || claims.IssuedAt.fractional ||
		claims.NotBefore.fractional || !notBefore.Equal(issuedAt) ||
		!expiresAt.Equal(issuedAt.Add(s.accessTokenTTL)) {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}

	subject, err := identity.ParseID(claims.Subject)
	if err != nil {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}
	if err := validateCanonicalUUIDV7(claims.DeviceID); err != nil {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}
	if err := validateCanonicalUUIDV7(claims.ID); err != nil {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}

	platformRole := identity.PlatformRoleNone
	if claims.PlatformRole == nil {
		if claims.platformRolePresent {
			return appauth.VerifiedAccessToken{}, ErrTokenInvalid
		}
	} else {
		if !claims.PlatformRole.IsAssigned() {
			return appauth.VerifiedAccessToken{}, ErrTokenInvalid
		}
		platformRole = *claims.PlatformRole
	}

	if issuedAt.After(now.Add(s.allowedClockSkew)) ||
		notBefore.After(now.Add(s.allowedClockSkew)) {
		return appauth.VerifiedAccessToken{}, ErrTokenInvalid
	}
	if !now.Before(expiresAt.Add(s.allowedClockSkew)) {
		return appauth.VerifiedAccessToken{}, ErrTokenExpired
	}

	return appauth.VerifiedAccessToken{
		Subject:      subject,
		DeviceID:     claims.DeviceID,
		PlatformRole: platformRole,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		JTI:          claims.ID,
	}, nil
}

func validateCanonicalUUIDV7(rawID string) error {
	parsedID, err := uuid.Parse(rawID)
	if err != nil {
		return err
	}

	if parsedID.Version() != 7 ||
		parsedID.Variant() != uuid.RFC4122 ||
		parsedID.String() != rawID {
		return errors.New("ID must be a canonical UUID v7")
	}

	return nil
}

var _ interface {
	Issue(appauth.AccessTokenClaims) (string, time.Time, error)
	Verify(string, time.Time) (appauth.VerifiedAccessToken, error)
} = (*RS256)(nil)
