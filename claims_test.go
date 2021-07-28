package grappa_test

import (
	"testing"

	"github.com/golang-jwt/jwt"

	"github.com/stevecallear/grappa"
	"github.com/stevecallear/grappa/proto/grappapb"
)

func TestVerifyIssuer(t *testing.T) {
	const issuer = "issuer"

	tests := []struct {
		name  string
		input jwt.MapClaims
		err   bool
	}{
		{
			name:  "should return an error if the issuer claim is missing",
			input: jwt.MapClaims{},
			err:   true,
		},
		{
			name:  "should return an error if the issuer claim is invalid",
			input: jwt.MapClaims{"iss": "invalid"},
			err:   true,
		},
		{
			name:  "should return nil if the issuer claim is valid",
			input: jwt.MapClaims{"iss": issuer},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := grappa.VerifyIssuer(issuer)(grappa.Context{}, tt.input)
			assertErrorExists(t, err, tt.err)
		})
	}
}

func TestVerifyAudience(t *testing.T) {
	var audience = []string{"audience_a", "audience_b"}

	tests := []struct {
		name  string
		input jwt.MapClaims
		err   bool
	}{
		{
			name:  "should return an error if the issuer claim is missing",
			input: jwt.MapClaims{},
			err:   true,
		},
		{
			name:  "should return an error if the issuer claim is invalid",
			input: jwt.MapClaims{"aud": "invalid"},
			err:   true,
		},
		{
			name:  "should return nil if the issuer claim is valid",
			input: jwt.MapClaims{"aud": audience[1]},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := grappa.VerifyAudience(audience)(grappa.Context{}, tt.input)
			assertErrorExists(t, err, tt.err)
		})
	}
}

func TestVerifyScope(t *testing.T) {
	var rule = &grappapb.Rule{
		RequireScope: []string{"scope_a", "scope_b"},
	}

	tests := []struct {
		name  string
		input jwt.MapClaims
		err   bool
	}{
		{
			name:  "should return false if the scope claim is missing",
			input: jwt.MapClaims{},
			err:   true,
		},
		{
			name:  "should return false if none of the required scopes are satisfied",
			input: jwt.MapClaims{"scope": "scope_c"},
			err:   true,
		},
		{
			name:  "should return true if the at least one required scope is satisfied",
			input: jwt.MapClaims{"scope": "scope_b scope_c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := grappa.VerifyScope()(grappa.Context{
				Rule: rule,
			}, tt.input)

			assertErrorExists(t, err, tt.err)
		})
	}
}
