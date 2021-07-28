package grappa

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Options represents a set of auth options
type Options struct {
	TokenFn         func(Context, metadata.MD) (string, bool)
	KeyFn           func(Context, *jwt.Token) (interface{}, error)
	ErrorFn         func(Context, error) error
	ClaimsVerifiers []VerifyFunc
	ClaimsMap       map[string]string
	Optional        bool
}

var defaultOptions = Options{
	TokenFn: func(_ Context, md metadata.MD) (string, bool) {
		vs := md.Get("authorization")
		if len(vs) < 1 || len(vs[0]) < 7 || !strings.EqualFold(vs[0][:7], "bearer ") {
			return "", false
		}

		return vs[0][7:], true
	},
	KeyFn: func(Context, *jwt.Token) (interface{}, error) {
		return nil, errors.New("authorization key not set")
	},
	ErrorFn: func(Context, error) error {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	},
	ClaimsVerifiers: []VerifyFunc{},
	ClaimsMap:       map[string]string{},
}

// HMAC configures the middleware to use the specified HMAC key
func HMAC(key []byte) func(*Options) {
	return func(o *Options) {
		o.KeyFn = func(_ Context, t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method: %s", t.Header["alg"])
			}

			return key, nil
		}
	}
}

// RSA configures the middleware to use the specified RSA PEM key
func RSA(key *rsa.PublicKey) func(*Options) {
	return func(o *Options) {
		o.KeyFn = func(_ Context, t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("invalid signing method: %s", t.Header["alg"])
			}

			return key, nil
		}
	}
}

// VerifyClaims configues the authorizor to use default issuer, audience and scope verification
func VerifyClaims(iss, aud string) func(*Options) {
	return func(o *Options) {
		o.ClaimsVerifiers = append(o.ClaimsVerifiers,
			VerifyIssuer(iss),
			VerifyAudience([]string{aud}),
			VerifyScope())
	}
}

// CaptureClaim configures the authorizor to cature the value of the claim
// and store it in the request metadata with the specified key
// e.g. grappa.CaptureClaim("sub", "auth.sub")
func CaptureClaim(claim, metadataKey string) func(*Options) {
	return func(o *Options) {
		if o.ClaimsMap == nil {
			o.ClaimsMap = map[string]string{
				claim: metadataKey,
			}
			return
		}

		o.ClaimsMap[claim] = metadataKey
	}
}

// Optional configures the authorizor to allow anonymous access to methods that
// do not have a rule specified
func Optional(o *Options) {
	o.Optional = true
}
