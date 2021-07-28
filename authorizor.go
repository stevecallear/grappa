package grappa

import (
	"context"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/stevecallear/grappa/internal/convert"
	"github.com/stevecallear/grappa/proto/grappapb"
)

type (
	// Registry represents a rule registry
	Registry interface {
		Register(pattern string, r *grappapb.Rule)
	}

	// Authorizor represents a jwt authorizor
	Authorizor struct {
		opts  Options
		rules []rule
	}

	// Context represents a request context
	Context struct {
		ID         string
		FullMethod string
		Rule       *grappapb.Rule
	}

	rule struct {
		rule    *grappapb.Rule
		matchFn func(pattern string) bool
	}
)

// New returns a new authorizor for the specified options
func New(optFns ...func(*Options)) *Authorizor {
	o := defaultOptions

	for _, fn := range optFns {
		fn(&o)
	}

	return &Authorizor{
		opts:  o,
		rules: []rule{},
	}
}

// Register registers the rule for the specified method pattern
func (a *Authorizor) Register(pattern string, r *grappapb.Rule) {
	a.rules = append(a.rules, rule{
		rule:    r,
		matchFn: newMatcher(pattern),
	})
}

// UnaryInterceptor is a unary interceptor func
func (a *Authorizor) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := a.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func (a *Authorizor) authorize(ctx context.Context, fullMethod string) (context.Context, error) {
	rctx := Context{
		ID:         uuid.NewString(),
		FullMethod: fullMethod,
	}

	rule, err := a.getRule(fullMethod)
	if err != nil {
		return nil, a.opts.ErrorFn(rctx, err)
	}

	rctx.Rule = rule

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, a.opts.ErrorFn(rctx, err)
	}

	token, ok := a.opts.TokenFn(rctx, md)
	if !ok {
		if rctx.Rule.AllowAnonymous {
			return ctx, nil
		}
		return nil, a.opts.ErrorFn(rctx, errors.New("invalid authorization"))
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		k, err := a.opts.KeyFn(rctx, t)
		if err != nil {
			return nil, err
		}

		return k, nil
	})
	if err != nil {
		return nil, a.opts.ErrorFn(rctx, err)
	}

	if err = a.verifyClaims(rctx, claims); err != nil {
		return nil, a.opts.ErrorFn(rctx, err)
	}

	return metadata.NewIncomingContext(ctx, a.captureClaims(md, claims)), nil
}

func (a *Authorizor) getRule(fullMethod string) (*grappapb.Rule, error) {
	for _, r := range a.rules {
		if r.matchFn(fullMethod) {
			return r.rule, nil
		}
	}

	if a.opts.Optional {
		return &grappapb.Rule{AllowAnonymous: true}, nil
	}

	return nil, errors.New("rule not found")
}

func (a *Authorizor) verifyClaims(ctx Context, c jwt.MapClaims) error {
	for _, fn := range a.opts.ClaimsVerifiers {
		if err := fn(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func (a *Authorizor) captureClaims(md metadata.MD, c jwt.MapClaims) metadata.MD {
	md = md.Copy()
	for ck, mk := range a.opts.ClaimsMap {
		if cv, ok := c[ck]; ok {
			md.Append(mk, convert.ToString(cv))
		}
	}

	return md
}

func newMatcher(pattern string) func(string) bool {
	if strings.HasSuffix(pattern, "*") {
		pre := strings.ToLower(pattern[:len(pattern)-1])
		return func(v string) bool {
			return strings.HasPrefix(strings.ToLower(v), pre)
		}
	}

	return func(v string) bool {
		return strings.EqualFold(v, pattern)
	}
}
