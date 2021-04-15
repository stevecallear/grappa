package generator_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/stevecallear/grappa/internal/generator"
)

func TestNew(t *testing.T) {
	req, err := os.Open("./testdata/code_generator_request.pb.bin")
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	pgs.Init(
		pgs.ProtocInput(req),
		pgs.ProtocOutput(buf)).
		RegisterModule(generator.New()).
		RegisterPostProcessor(pgsgo.GoFmt()).
		Render()

	gen := buf.String()
	tests := []struct {
		name   string
		assert func(*testing.T, string)
	}{
		{
			name: "should not generate empty files",
			assert: func(t *testing.T, gen string) {
				if strings.Contains(gen, "source: internal/module/testdata/with_rules.proto") {
					t.Errorf("got %s, expected no generated code for no_rules.proto", gen)
				}
			},
		},
		{
			name: "should not generate empty register funcs",
			assert: func(t *testing.T, gen string) {
				if strings.Contains(gen, "func RegisterNoRuleServiceServerRules") {
					t.Errorf("got %s, expected no generated code for NoRuleService", gen)
				}
			},
		},
		{
			name: "should generate correct register funcs for allow_anonymous",
			assert: func(t *testing.T, gen string) {
				if !strings.Contains(gen, allowAnonExp) {
					t.Errorf("got %s, expected a correct register func for AllowAnonService", gen)
				}
			},
		},
		{
			name: "should generate correct register funcs for require_scope",
			assert: func(t *testing.T, gen string) {
				if !strings.Contains(gen, requireScopeExp) {
					t.Errorf("got %s, expected a correct register func for RequireScopeService", gen)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, gen)
		})
	}
}

const (
	allowAnonExp = `func RegisterAllowAnonServiceServerRules(a grappa.Registry) {

	a.Register("/grappa.test.AllowAnonService/Method", &grappapb.Rule{
		AllowAnonymous: true,
		RequireScope:   []string{},
	})

}`

	requireScopeExp = `func RegisterRequireScopeServiceServerRules(a grappa.Registry) {

	a.Register("/grappa.test.RequireScopeService/Method", &grappapb.Rule{
		AllowAnonymous: false,
		RequireScope: []string{
			"scope_a",
			"scope_b",
		},
	})

}`
)
