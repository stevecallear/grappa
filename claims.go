package grappa

import (
	"errors"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// VerifyFunc represents a claims verification func
type VerifyFunc func(Context, jwt.MapClaims) error

// VerifyIssuer verifies the issuer claim
func VerifyIssuer(iss string) VerifyFunc {
	return func(_ Context, c jwt.MapClaims) error {
		if !c.VerifyIssuer(iss, true) {
			return errors.New("invalid issuer claim")
		}

		return nil
	}
}

// VerifyAudience verifies the audience claim
func VerifyAudience(aud []string) VerifyFunc {
	return func(_ Context, c jwt.MapClaims) error {
		var ok bool
		for _, a := range aud {
			ok = c.VerifyAudience(a, true)
			if ok {
				break
			}
		}

		if !ok {
			return errors.New("invalid audience claim")
		}

		return nil
	}
}

// VerifyScope verifies the scope claim
func VerifyScope() VerifyFunc {
	return func(ctx Context, c jwt.MapClaims) error {
		s, ok := getClaimStr(c, "scope")
		if !ok {
			return errors.New("invalid scope claim")
		}

		ss := strings.Fields(s)
		for _, rs := range ctx.Rule.GetRequireScope() {
			for _, cs := range ss {
				if strings.EqualFold(rs, cs) {
					return nil
				}
			}
		}

		return errors.New("invalid scope claim")
	}
}

func getClaimStr(c jwt.MapClaims, claim string) (string, bool) {
	if v, ok := c[claim]; ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}

	return "", false
}
