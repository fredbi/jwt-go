// Package fetchers provide some classical implementations for jWKS fetchers.
//
// It relies on the popular go implementation of JWK github.com/square/go-jose.
package fetchers

import (
	"github.com/dgrijalva/jwt-go/jwks"
	jose "gopkg.in/square/go-jose.v2"
)

// JSONWebKeySet wraps gopkg.in/square/go-jose.v2.JSONWebKeySet to expose struct as an interface
type JSONWebKeySet struct {
	jose.JSONWebKeySet
}

// Key returns all keys in the set that match a KID
func (s JSONWebKeySet) Key(kid string) []jwks.JSONWebKey {
	keys := s.JSONWebKeySet.Key(kid)
	result := make([]jwks.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, jwks.JSONWebKey(JSONWebKey{JSONWebKey: key}))
	}
	return result
}

// JSONWebKey wraps gopkg.in/square/go-jose.v2.JSONWebKeySet to expose struct as an interface
type JSONWebKey struct {
	jose.JSONWebKey
}

// Algorithm returns this key algorithm
func (k JSONWebKey) Algorithm() string { return k.JSONWebKey.Algorithm }

// Use indicates the intended usage for this key
func (k JSONWebKey) Use() string { return k.JSONWebKey.Use }

// Key structure
func (k JSONWebKey) Key() interface{} { return k.JSONWebKey.Key }

// Valid checks if key is valid
func (k JSONWebKey) Valid() bool { return k.JSONWebKey.Valid() }

// KID returns the key ID
func (k JSONWebKey) KID() string { return k.JSONWebKey.KeyID }

// type safeguard
var _ jwks.Fetcher = &DefaultFetcher{}

// DefaultFetcher simply returns some preconfigured JSON keyset
//
// DefaultFetcher provides a basic implementation, essentially for testing purpose.
// In practice, you'd need to provide an implementation of this interface to fetch the JWKS from some remote URL
// and unmarshal it into a JSONWebKeySet structure.
type DefaultFetcher struct {
	Keyset JSONWebKeySet
}

// Fetch yields a JWK set
func (f *DefaultFetcher) Fetch() (jwks.JSONWebKeySet, error) {
	return jwks.JSONWebKeySet(f.Keyset), nil
}

// NewDefaultFetcher builds a trivial JWKS fetcher that returns a preset set of keys
func NewDefaultFetcher(keys ...jose.JSONWebKey) jwks.Fetcher {
	return &DefaultFetcher{Keyset: JSONWebKeySet{JSONWebKeySet: jose.JSONWebKeySet{Keys: keys}}}
}

// TODO: UnmarshalJSON
// TODO: HTTPFetcher
