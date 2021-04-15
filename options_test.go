package grappa_test

import (
	"crypto/rsa"
	"testing"

	"github.com/dgrijalva/jwt-go"

	"github.com/stevecallear/grappa"
	"github.com/stevecallear/grappa/proto/grappapb"
)

func TestHMAC(t *testing.T) {
	key := []byte("key")
	tests := []struct {
		name   string
		key    []byte
		method jwt.SigningMethod
		exp    interface{}
		err    bool
	}{
		{
			name:   "should return an error if the signing method is invalid",
			key:    key,
			method: jwt.SigningMethodRS256,
			err:    true,
		},
		{
			name:   "should return the token if the signing method is valid",
			key:    key,
			method: jwt.SigningMethodHS256,
			exp:    key,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := grappa.Options{}
			grappa.HMAC(tt.key)(&opt)

			act, err := opt.KeyFn(grappa.Context{}, jwt.New(tt.method))

			assertErrorExists(t, err, tt.err)
			assertDeepEqual(t, act, tt.exp)
		})
	}
}

func TestRSA(t *testing.T) {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name   string
		key    *rsa.PublicKey
		method jwt.SigningMethod
		exp    interface{}
		err    bool
	}{
		{
			name:   "should return an error if the signing method is invalid",
			key:    key,
			method: jwt.SigningMethodHS256,
			err:    true,
		},
		{
			name:   "should return the token if the signing method is valid",
			key:    key,
			method: jwt.SigningMethodRS256,
			exp:    key,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := grappa.Options{}
			grappa.RSA(tt.key)(&opt)

			act, err := opt.KeyFn(grappa.Context{}, jwt.New(tt.method))

			assertErrorExists(t, err, tt.err)
			assertDeepEqual(t, act, tt.exp)
		})
	}
}

func TestVerifyClaims(t *testing.T) {
	t.Run("should add the claims verification funcs", func(t *testing.T) {
		var iss, aud, scope = "issuer", "audience", "scope"

		o := grappa.Options{}
		grappa.VerifyClaims(iss, aud)(&o)

		ctx := grappa.Context{
			Rule: &grappapb.Rule{
				RequireScope: []string{scope},
			},
		}

		clm := jwt.MapClaims{
			"iss":   iss,
			"aud":   aud,
			"scope": scope,
		}

		if len(o.ClaimsVerifiers) != 3 {
			t.Errorf("got %d, expected 3 funcs", len(o.ClaimsVerifiers))
		}

		for _, fn := range o.ClaimsVerifiers {
			err := fn(ctx, clm)
			assertErrorExists(t, err, false)
		}
	})
}

func TestCaptureClaim(t *testing.T) {
	tests := []struct {
		name        string
		options     grappa.Options
		claimKey    string
		metadataKey string
		exp         map[string]string
	}{
		{
			name:        "should store the values in the claims map",
			options:     grappa.Options{},
			claimKey:    "sub",
			metadataKey: "auth.sub",
			exp: map[string]string{
				"sub": "auth.sub",
			},
		},
		{
			name: "should overwrite existing values",
			options: grappa.Options{
				ClaimsMap: map[string]string{
					"sub": "sub",
				},
			},
			claimKey:    "sub",
			metadataKey: "auth.sub",
			exp: map[string]string{
				"sub": "auth.sub",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := tt.options
			grappa.CaptureClaim(tt.claimKey, tt.metadataKey)(&opt)

			assertDeepEqual(t, opt.ClaimsMap, tt.exp)
		})
	}
}

func TestOptional(t *testing.T) {
	t.Run("should set the optional flag to true", func(t *testing.T) {
		opt := grappa.Options{}
		grappa.Optional(&opt)

		if act, exp := opt.Optional, true; act != exp {
			t.Errorf("got %v, expected %v", act, exp)
		}
	})
}
