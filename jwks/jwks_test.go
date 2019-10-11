package jwks_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"path/filepath"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/jwks"
	"github.com/dgrijalva/jwt-go/jwks/fetchers"
	"gopkg.in/square/go-jose.v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rawKeySet struct {
	Keys []json.RawMessage `json:"keys"`
}

func iterateFixtures(t testing.TB) []jose.JSONWebKeySet {
	fixtures, err := filepath.Glob(filepath.Join(".", "fixtures", "jwks*.json"))
	require.NoError(t, err)
	result := make([]jose.JSONWebKeySet, 0, len(fixtures))
	for _, fixture := range fixtures {
		tc, errio := ioutil.ReadFile(fixture)
		require.NoErrorf(t, errio, "unexpected i/o error when reading %s", fixture)
		var (
			ks      jose.JSONWebKeySet
			rawKeys rawKeySet
		)

		// raw unmarshalling to capture erroneous keys
		errio = json.Unmarshal(tc, &rawKeys)
		require.NoErrorf(t, errio, "unexpected unmarshalling error %v when loading %s", errio, fixture)

		ks.Keys = make([]jose.JSONWebKey, 0, len(rawKeys.Keys))
		for _, jazon := range rawKeys.Keys {
			var k jose.JSONWebKey
			t.Logf("key: %s", string(jazon))
			err = json.Unmarshal(jazon, &k)
			if err != nil {
				t.Logf("warning: invalid key in keyset fixture %s: %v", fixture, err)
				continue
			}
			ks.Keys = append(ks.Keys, k)
		}
		t.Logf("jwks from %s: %v", fixture, ks)
		if len(ks.Keys) > 0 {
			result = append(result, ks)
		}
	}
	t.Logf("test JWKS: %v", result)
	return result
}

type testcase struct {
	name     string
	token    *jwt.Token
	asserter func(interface{}, error) bool
}

func makeTestTokens(t testing.TB, kset jose.JSONWebKeySet) []testcase {
	// derive a series of test tokens, depending on the JWKS at hand
	result := make([]testcase, 0, len(kset.Keys)*2)
	for _, k := range kset.Keys {
		// for each key, produce a token that matches
		var (
			method jwt.SigningMethod
		)

		switch k.Algorithm {
		case "HS256":
			method = jwt.SigningMethodHS256
		case "HS384":
			method = jwt.SigningMethodHS384
		case "HS512":
			method = jwt.SigningMethodHS512
		default:
			t.Logf("more test needed")
			t.FailNow()
		}
		result = append(result, testcase{
			token: &jwt.Token{
				Method: method,
				Header: map[string]interface{}{
					"kid": k.KeyID,
					"typ": "JWT",
					"alg": k.Algorithm,
				},
			},
			asserter: func(res interface{}, err error) bool {
				return assert.NoError(t, err) && assert.NotEmpty(t, res)
			},
		})
	}
	return result
}

func TestGetSigningKey(t *testing.T) {
	for i, keyset := range iterateFixtures(t) {
		//t.Parallel()
		t.Run(fmt.Sprintf("keyset %d", i), func(t *testing.T) {
			k := fetchers.NewDefaultFetcher(keyset.Keys...)
			keyGetter := jwks.NewKeyGetter(jwks.WithFetcher(k))
			for _, tc := range makeTestTokens(t, keyset) {
				t.Logf("test token: %v", tc.token)
				assert.True(t, tc.asserter(keyGetter.GetSigningKey(tc.token)))
			}
		})
	}
}

func ExampleKeyGetter() {
	rawToken := "abv"
	key1 := jose.JSONWebKey{}
	key2 := jose.JSONWebKey{}

	stdClaims := jwt.StandardClaims{}
	p := jwt.Parser{}

	keyset := fetchers.NewDefaultFetcher(key1, key2)

	g := jwks.NewKeyGetter(jwks.WithFetcher(keyset))

	token, err := p.ParseWithClaims(rawToken, &stdClaims, g.GetSigningKey)
	if err != nil {
		log.Printf("error: %v", err)
	}
	log.Printf("token: %#v", token)
}

// Filtering signing keys of RS type:
//
//   token, err := p.ParseWithClaims(rawToken, &stdClaims, jwks.NewKeyGetter(WithAlgorithms(jwks.RS), WithFetcher(keyset)).GetSigningKey)

/*
// verifyToken verifies a JWT token against its signing key then return the claims in the token.
func (m *Authorizer) verifyToken(token string) (*Claims, error) {
	stdClaims := Claims{}
	// strip token from trailing space or line feed
	cleanToken := rexStripper.ReplaceAllString(token, "")

	if token == "" {
		return nil, ErrNoToken
	}

	p := jwt.Parser{
		// JSON numbers parsed as float
		UseJSONNumber: false,
		// A list of supported signing "alg" strings
		ValidMethods: []string{
			"HS256", "HS384", "HS512", // symmetric (HMAC)
			"RS256", "RS384", "RS512", // RSA
			"PS256", "PS384", "PS512", // RSA-PSS
			"ES256", "ES384", "ES512", // EC-DSA elliptic curves
		},
		// We skip internal claim validation and carry out our own validations
		// (e.g. time-based constraints)
		SkipClaimsValidation: true,
	}

	_, err := p.ParseWithClaims(cleanToken, &stdClaims, m.getSigningKey)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization token provided: %v", err)
	}
	return &stdClaims, nil
}
*/
