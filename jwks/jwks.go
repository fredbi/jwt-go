package jwks

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	// Errors returned by jwks

	// ErrNilToken complains about an empty token
	ErrNilToken = errors.New("passed a nil token")

	// ErrNoFetcher indicates that no JWKS fetcher has been configured
	ErrNoFetcher = errors.New("no JWKS fetcher configured")

	// ErrInvalidTokenHeaderNoKid complains that there is no kid claim to identify the signer
	ErrInvalidTokenHeaderNoKid = errors.New("invalid token header: missing kid")

	// ErrInvalidTokenHeaderWrongKid complains that the kid claim cannot be unmarshalled (expect a string)
	ErrInvalidTokenHeaderWrongKid = errors.New("invalid token header: invalid kid type")

	// ErrInvalidSigningRSAKey complains that the RSA key provided is not well-formed
	ErrInvalidSigningRSAKey = errors.New("invalid signing RSA key")

	// ErrInvalidSigningRSAKeyType complains that the RSA key provided is not of the expected type *crypto/rsa.PublicKey
	ErrInvalidSigningRSAKeyType = errors.New("signing key type RSA does not match with token signing algorithm")

	// ErrInvalidSigningHMACKeyType complains that the HMAC key provided is not of the expected type []byte
	ErrInvalidSigningHMACKeyType = errors.New("signing key type HMAC does not match with token signing algorithm")

	// ErrInvalidSigningECDSAKey complains that the ECDSA key provided is not well-formed
	ErrInvalidSigningECDSAKey = errors.New("invalid signing ECDSA key")

	// ErrInvalidSigningECDSAKeyType complains that the ECDSA key provided is not of the expected type *crypto/ecsda.PublicKey
	ErrInvalidSigningECDSAKeyType = errors.New("signing key type ECDSA does not match with token signing algorithm")

	// ErrUnauthoritativeSigningKey complains that the signing key provided was not found in the authoritative set of keys
	ErrUnauthoritativeSigningKey = errors.New("unauthoritative signing key for token")

	// ErrUnsupportedSigningMethod
	ErrUnsupportedSigningMethod = errors.New("unsupported token signing method")
)

// JSONWebKeySet defines the expectations from a JWKS implementation (e.g. gopkg.in/square/go-jose.v2.JSONWebKeySet)
type JSONWebKeySet interface {
	// Key returns the key in the JWKS indexed by its KID. It might not be unique.
	Key(string) []JSONWebKey
}

// JSONWebKey defines the expectations from a JWK implementation (e.g. wraps gopkg.in/square/go-jose.v2.JSONWebKey)
type JSONWebKey interface {
	// Valid checks that the key is valid
	Valid() bool
	// Algorithm returns the key signature algorithm
	Algorithm() string
	// Use returns the key intended usage
	Use() string
	// Key return the key parameters (e.g. *rsa.PublicKey, etc...)
	Key() interface{}
	// KID return the key ID
	KID() string
}

// Fetcher knows how to retrieve a JWK set from some JWKS location. See package fetchers to pick an implementation.
type Fetcher interface {
	// Fetch yields a JWK set
	Fetch() (JSONWebKeySet, error)
}

// KeyGetter pick a signing key for a token to verifiy from a JWK set of authoritative keys
type KeyGetter struct {
	useAlgorithms        []Algorithm
	useOnlySignatureKeys *bool
	fetcher              Fetcher
}

// Algorithm represents a JWK standard signature algorithm
type Algorithm string

func (a Algorithm) String() string { return string(a) }

const (
	// HS stands for any HMAC based key
	HS Algorithm = "HS"
	// HS256 stands for HMAC-256 based key
	HS256 Algorithm = "HS256"
	// HS384 stands for HMAC-384 based key
	HS384 Algorithm = "HS384"
	// HS512 stands for HMAC-512 based key
	HS512 Algorithm = "HS512"

	// RS stands for any RSA based key
	RS Algorithm = "RS"
	// RS256 stands for RSA-256 based key
	RS256 Algorithm = "RS256"
	// RS384 stands for RSA-384 based key
	RS384 Algorithm = "RS384"
	// RS512 stands for RSA-512 based key
	RS512 Algorithm = "RS512"

	// ES stands for any ECDSA based key
	ES Algorithm = "ES"
	// ES256 stands for ECDSA-256 based key
	ES256 Algorithm = "ES256"
	// ES384 stands for ECDSA-384 based key
	ES384 Algorithm = "ES384"
	// ES512 stands for ECDSA-512 based key
	ES512 Algorithm = "ES512"

	// PS stands for any RSA-PSS based key
	PS Algorithm = "PS"
	// PS256 stands for RSA-PSS-256 based key
	PS256 Algorithm = "PS256"
	// PS384 stands for RSA-PSS-384 based key
	PS384 Algorithm = "PS384"
	// PS512 stands for RSA-PSS-512 based key
	PS512 Algorithm = "PS512"
)

// Option for the KeyGetter
type Option func(*KeyGetter)

// WithAlgorithms restrict the list of supported signature algorithms to be extracted from a JWKS.
// By default, all supported algorithms are eligible.
func WithAlgorithms(algs ...Algorithm) Option {
	return func(kg *KeyGetter) {
		kg.useAlgorithms = append(kg.useAlgorithms, algs...)
	}
}

// WithFetcher indicates which Fetcher to use to retrieve a JWKS
func WithFetcher(fetcher Fetcher) Option {
	return func(kg *KeyGetter) {
		kg.fetcher = fetcher
	}
}

func flagArgs(flags []bool) *bool {
	flag := false
	if len(flags) == 0 {
		flag = true
	} else {
		flag = flags[len(flags)-1]
	}
	return &flag
}

// OnlySigKeys indicates that only keys with usage "sig" are considered. This is the default.
// Use WithOnlySignatureKeys(false) to extend to all kind keys.
//
// When called with no argument, implies true.
func OnlySigKeys(flags ...bool) Option {
	return func(kg *KeyGetter) {
		kg.useOnlySignatureKeys = flagArgs(flags)
	}
}

// NewKeyGetter builds a JWKS getter
func NewKeyGetter(opts ...Option) *KeyGetter {
	v := new(KeyGetter)
	//applyDefaults(v)
	for _, apply := range opts {
		apply(v)
	}
	return v
}

// supportsAlgorithm provides an optional extra check against the algorithm
// stated in the JWKS.
func (v KeyGetter) supportsAlgorithm(alg string) bool {
	if len(v.useAlgorithms) == 0 {
		return true
	}
	for _, supported := range v.useAlgorithms {
		s := supported.String()
		if alg[0:2] == s || alg == s {
			return true
		}
	}
	return false
}

// GetSigningKey retrieves a signing key from a signing authority given a
// raw parsed token providing a kid identifier in the header.
//
// This function searches for the kid provided in the token header and verifies
// this against a JWKS set fetched from some configured signing authority.
func (v KeyGetter) GetSigningKey(parsedToken *jwt.Token) (interface{}, error) {
	// safeguard for minimal valid token structure
	if parsedToken == nil {
		return nil, ErrNilToken
	}
	if v.fetcher == nil {
		return nil, ErrNoFetcher
	}
	value, ok := parsedToken.Header["kid"]
	if !ok {
		return nil, ErrInvalidTokenHeaderNoKid
	}
	kid, ok := value.(string)
	if !ok {
		return nil, ErrInvalidTokenHeaderWrongKid
	}

	// check alg claim
	keySet, err := v.fetcher.Fetch()
	if err != nil {
		return nil, fmt.Errorf("error resolving signing keys set: %v", err)
	}
	for _, key := range keySet.Key(kid) {
		if key == nil {
			continue
		}
		if (v.useOnlySignatureKeys == nil || *v.useOnlySignatureKeys) && key.Use() != "sig" {
			// not interested in keys not intended for signature
			continue
		}
		if !v.supportsAlgorithm(key.Algorithm()) {
			// skips algorithms we don't want to support
			continue
		}

		method := parsedToken.Method
		if method == nil {
			return nil, ErrUnsupportedSigningMethod
		}
		if method.Alg() != key.Algorithm() {
			// skips keys with different alg than token
			continue
		}

		switch method := method.(type) {
		case *jwt.SigningMethodRSA:
			if !key.Valid() {
				return nil, ErrInvalidSigningRSAKey
			}
			rsaKey, ok := key.Key().(*rsa.PublicKey)
			if !ok {
				return nil, ErrInvalidSigningRSAKeyType
			}
			return rsaKey, nil
		case *jwt.SigningMethodRSAPSS:
			if !key.Valid() {
				return nil, ErrInvalidSigningRSAKey
			}
			rsaKey, ok := key.Key().(*rsa.PublicKey)
			if !ok {
				return nil, ErrInvalidSigningRSAKeyType
			}
			return rsaKey, nil
		case *jwt.SigningMethodHMAC:
			hmacKey, ok := key.Key().([]byte)
			if !ok {
				return nil, ErrInvalidSigningHMACKeyType
			}
			return hmacKey, nil
		case *jwt.SigningMethodECDSA:
			if !key.Valid() {
				return nil, ErrInvalidSigningECDSAKey
			}
			ecdsaKey, ok := key.Key().(*ecdsa.PublicKey)
			if !ok {
				return nil, ErrInvalidSigningECDSAKeyType
			}
			return ecdsaKey, nil
		default:
			return nil, fmt.Errorf("unsupported key type: %T", method)
		}
	}
	return nil, ErrUnauthoritativeSigningKey
}
