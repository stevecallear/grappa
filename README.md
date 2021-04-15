# grappa
[![Build Status](https://travis-ci.org/stevecallear/grappa.svg?branch=master)](https://travis-ci.org/stevecallear/grappa)
[![codecov](https://codecov.io/gh/stevecallear/grappa/branch/master/graph/badge.svg)](https://codecov.io/gh/stevecallear/grappa)
[![Go Report Card](https://goreportcard.com/badge/github.com/stevecallear/grappa)](https://goreportcard.com/report/github.com/stevecallear/grappa)

`grappa` offers a protoc plugin to generate and register method authorization rules directly from `.proto` definitions and a supporting JWT interceptor to validate the generated rules on method invocation.

The module started as an experiment combining [`protoc-gen-star`](https://github.com/lyft/protoc-gen-star) for plugin creation, with [`jwt-go`](https://github.com/dgrijalva/jwt-go) for token validation to simplify the creation of JWT middleware for GRPC services written in Go.

## Getting started
```
go get github.com/stevecallear/grappa
go install github.com/stevecallear/grappa/cmd/protoc-gen-grappa
```

`grappa` uses a custom `MethodOptions` extension to allow per-method rules to be generated. The following `.proto` definition configures an anonymous method, and another that requires the request authorization to contain the `user` scope.
```
syntax = "proto3";
package example;

import "google/protobuf/empty.proto";
import "grappapb/annotations.proto";

option go_package = "github.com/org/repo/proto/example";

service ExampleService {    
    rpc MethodA(google.protobuf.Empty) returns (google.protobuf.Empty) {
        option (grappa.rule) = {
            allow_anonymous: True
        };
    }

    rpc MethodB(google.protobuf.Empty) returns (google.protobuf.Empty) {
        option (grappa.rule) = {
            allow_anonymous: False
            require_scope: "user"
        };
    }
}
```

Supporting Go code can then be generated using the `protoc-gen-grappa` plugin.
```
protoc -I. --proto_path="/path/to/proto" --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. ./proto/*.proto
protoc -I. --proto_path="/path/to/proto" --grappa_out=paths=source_relative:. ./proto/*.proto
```

This will generate `example.pb.grappa.go` alongside the standard protobuf/GRPC outputs. The rules can then be registered as a method interceptor.
```
auth := grappa.New(grappa.RSA(publicKey), grappa.VerifyClaims("issuer.com", "audience.com"))
example.RegisterExampleServiceServerRules(auth)

svr := grpc.NewServer(grpc.UnaryInterceptor(auth.UnaryInterceptor))
example.RegisterExampleServiceServer(svr, service)

svr.Serve(listener)
```
> Note: the `VerifyClaims` option is required to evaluate the `require_scope` definition. This adds claim verification for `iss`, `aud` and `scope`.

## Configuration
`grappa.New` returns a configured JWT authorizer that exposes a unary interceptor function. A stream interceptor is not currently implemented.

By default the options will extract the JWT bearer token from an `Authorization` header and will return `codes.Unauthenticated` for all errors. Further customisation is available by supplying one or more option functions with the signature `func (o *grappa.Options)`.

The default `KeyFn` will return an error for all requests, so must be configured. `grappa.HMAC` and `grappa.RSA` can be used to configure HMAC and RSA keys respectively.

### Anonymous access
Per-method anonymous access can be configured by specifying `allow_anonymous` in the proto definition.

By default `grappa` will return an error in scenarios where no rule has been configured. This ensures that all methods require authorization unlesss explicitly granted anonymous access. To override this behaviour, the `grappa.Optional` option can be supplied, which will grant anonymous access to all methods unless they have a rule defined that requires authorization.
```
auth := grappa.New(grappa.RSA(publicKey), grappa.Optional)
```

### Claims verification
By default, claims are validated as per the behaviour of `jwt-go`. In addition, the `grappa.VerifyClaims` option can be supplied to verify the issuer, audience and required scopes.
```
auth := grappa.New(grappa.RSA(publicKey), grappa.VerifyClaims("issuer.com", "audience.com"))
```

Custom verifiers that satisfy the `grappa.VerifyFunc` signature can be configured as required.
```
auth := grappa.New(grappa.RSA(publicKey), func(o *grappa.Options) {
    o.ClaimsVerifiers = append(o.ClaimsVerifiers, func(ctx grappa.Context, c jwt.MapClaims) error {
        if v, ok := c["claim"]; ok {
            s, _ := v.(string)
            if s == "expected value" {
                return nil
            }
        }
        return errors.New("invalid claim")
    })
})
```

Verifiers are executed in the order that they are present within the `ClaimsVerifiers` slice.

### Claims capture
If the server needs to evaluate token claims, such as the subject then they can be extracted using `grappa.CaptureClaim`.
```
auth := grappa.New(grappa.RSA(publicKey), grappa.CaptureClaim("sub", "auth.sub"))
```

This will result in the string value of the claim being available in the context metadata:
```
if md, ok := metadata.FromIncomingContext(ctx); ok {
    if vs := md.Get("auth.sub"); len(vs) > 0 {
        log.Println(vs[0])
    }
}
```

### Wildcard rules
It is possible to register rules for external services, these can include a trailing wildcard. For example, the following will grant anonymous access to all health check methods.
```
auth := grappa.New(grappa.HMAC(key))
example.RegisterExampleServiceServerRules(auth)

auth.Register("/grpc.health/v1.Health/*", &grappapb.Rule{
    AllowAnonymous: true,
})
```

### Error handling
By default the authorizor will return `codes.Unauthenticated` for all errors to avoid leaking internal information. It is possible to override this behaviour to implement logging or error customisation.
```
auth := grappa.New(grappa.RSA(publicKey), func(o *grappa.Options) {
    o.ErrorFn = func(ctx grappa.Context, err error) error {
        log.Printf("%s %s: %v", ctx.ID, ctx.FullMethod, err)
        return status.Error(codes.Unauthenticated, "unauthenticated")
    }
})
```