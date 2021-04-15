package grappa_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stevecallear/grappa"
	"github.com/stevecallear/grappa/proto/grappapb"
)

func init() {
	jwt.NoneSignatureTypeDisallowedError = nil
}

func TestNew_DefaultOptions_UnaryInterceptor(t *testing.T) {
	info := &grpc.UnaryServerInfo{
		FullMethod: "/package.Service/Method",
	}

	authErr := status.Error(codes.Unauthenticated, "")

	tests := []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{
			name: "should return unauthenticated if the metadata is invalid",
			ctx:  context.Background(),
			err:  authErr,
		},
		{
			name: "should return unauthenticated if the authorization header is not set",
			ctx:  metadata.NewIncomingContext(context.Background(), make(metadata.MD)),
			err:  authErr,
		},
		{
			name: "should return unauthenticated if the authorization header is empty",
			ctx:  metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "")),
			err:  authErr,
		},
		{
			name: "should return unauthenticated if the authorization header is invalid",
			ctx:  metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "basic credentials")),
			err:  authErr,
		},
		{
			name: "should return unauthenticated if the key fn is not set",
			ctx:  metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+newNone(nil))),
			err:  authErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := grappa.New()
			sut.Register(info.FullMethod, new(grappapb.Rule))

			_, err := sut.UnaryInterceptor(tt.ctx, nil, info, grpc.UnaryHandler(func(context.Context, interface{}) (interface{}, error) {
				t.Errorf("got handler invocation, expected no invocation")
				return nil, nil
			}))

			assertErrorEqual(t, err, tt.err)
		})
	}
}

func TestNew_UnaryInterceptor(t *testing.T) {
	now := time.Now().UTC()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/package.Service/Method",
	}

	tests := []struct {
		name    string
		options func(*grappa.Options)
		setup   func(*grappa.Authorizor)
		ctx     context.Context
		handler grpc.UnaryHandler
		exp     interface{}
		err     bool
	}{
		{
			name: "should not require a token for missing rules if the authorizor is configured to be optional",
			options: func(o *grappa.Options) {
				o.Optional = true
			},
			setup: func(a *grappa.Authorizor) {},
			ctx:   metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return "response", nil
			},
			exp: "response",
		},
		{
			name:    "should not require a token if the rule is configured to allow anonymous",
			options: func(o *grappa.Options) {},
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, &grappapb.Rule{
					AllowAnonymous: true,
				})
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return "response", nil
			},
			exp: "response",
		},
		{
			name:    "should require a token for missing rules if the authorizor is not configured to be optional",
			options: func(o *grappa.Options) {},
			setup: func(a *grappa.Authorizor) {
				a.Register("/package.Service/AnotherMethod", &grappapb.Rule{AllowAnonymous: true})
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return nil, nil
			},
			err: true,
		},
		{
			name: "should reject invalid tokens",
			options: func(o *grappa.Options) {
				o.TokenFn = func(grappa.Context, metadata.MD) (string, bool) {
					return newNone(map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(-1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(grappa.Context, *jwt.Token) (interface{}, error) {
					return nil, nil
				}
			},
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, &grappapb.Rule{})
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return nil, nil
			},
			err: true,
		},
		{
			name: "should execute claims verification funcs",
			options: func(o *grappa.Options) {
				o.TokenFn = func(grappa.Context, metadata.MD) (string, bool) {
					return newRSA([]byte(rsaPrivateKey), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(grappa.Context, *jwt.Token) (interface{}, error) {
					return jwt.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
				}
				o.ClaimsVerifiers = []grappa.VerifyFunc{
					func(grappa.Context, jwt.MapClaims) error {
						return errors.New("error")
					},
				}
			},
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, new(grappapb.Rule))
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return nil, nil
			},
			err: true,
		},
		{
			name: "should execute the handler if the token is valid",
			options: func(o *grappa.Options) {
				o.TokenFn = func(grappa.Context, metadata.MD) (string, bool) {
					return newRSA([]byte(rsaPrivateKey), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(grappa.Context, *jwt.Token) (interface{}, error) {
					return jwt.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
				}
			},
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, &grappapb.Rule{})
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(context.Context, interface{}) (interface{}, error) {
				return "response", nil
			},
			exp: "response",
		},
		{
			name: "should copy mapped claims into context metadata",
			options: func(o *grappa.Options) {
				o.TokenFn = func(grappa.Context, metadata.MD) (string, bool) {
					return newHMAC([]byte("secretkey"), map[string]interface{}{
						"sub": "subject",
						"iat": now.Add(-1 * time.Hour).Unix(),
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(grappa.Context, *jwt.Token) (interface{}, error) {
					return []byte("secretkey"), nil
				}
				o.ClaimsMap = map[string]string{
					"sub": "auth.sub",
					"iat": "auth.iat",
				}
			},
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, &grappapb.Rule{})
			},
			ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{}),
			handler: func(ctx context.Context, _ interface{}) (interface{}, error) {
				md, _ := metadata.FromIncomingContext(ctx)
				s := md.Get("auth.sub")
				i := md.Get("auth.iat")

				return s[0] + " " + i[0], nil
			},
			exp: fmt.Sprintf("subject %v", now.Add(-1*time.Hour).Unix()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := grappa.New(tt.options)
			tt.setup(sut)

			act, err := sut.UnaryInterceptor(tt.ctx, nil, info, tt.handler)

			assertErrorExists(t, err, tt.err)

			if act != tt.exp {
				t.Errorf("got %v, expected %v", act, tt.exp)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	info := &grpc.UnaryServerInfo{
		FullMethod: "/package.Service/Method",
	}

	tests := []struct {
		name  string
		setup func(*grappa.Authorizor)
	}{
		{
			name: "should support exact pattern registration",
			setup: func(a *grappa.Authorizor) {
				a.Register(info.FullMethod, &grappapb.Rule{
					AllowAnonymous: true,
				})
			},
		},
		{
			name: "should support wildcard pattern registration",
			setup: func(a *grappa.Authorizor) {
				a.Register("/package.Service/*", &grappapb.Rule{
					AllowAnonymous: true,
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sut := grappa.New()
			tt.setup(sut)

			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
			act, err := sut.UnaryInterceptor(ctx, nil, info, func(context.Context, interface{}) (interface{}, error) {
				return "response", nil
			})

			assertErrorExists(t, err, false)
			if act != "response" {
				t.Errorf("got %v, expected response", act)
			}
		})
	}
}
