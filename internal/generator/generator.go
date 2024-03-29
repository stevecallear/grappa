package generator

import (
	"fmt"
	"strings"
	"text/template"

	"google.golang.org/protobuf/proto"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"

	"github.com/stevecallear/grappa/proto/grappapb"
)

type (
	// Generator represents a protoc generator module
	Generator struct {
		*pgs.ModuleBase
		ctx pgsgo.Context
		tpl *template.Template
	}

	file struct {
		InputPath string
		Package   string
		Services  []service
	}

	service struct {
		Name    string
		Methods []method
	}

	method struct {
		Pattern string
		*grappapb.Rule
	}
)

const templateStr = `// Code generated by protoc-gen-grappa. DO NOT EDIT.
// source: {{ .InputPath }}

package {{ .Package }}

import (
	"github.com/stevecallear/grappa"
	"github.com/stevecallear/grappa/proto/grappapb"
)

{{ range .Services }}
func Register{{ .Name }}Rules(a grappa.Registry){
{{ range .Methods }}
	a.Register("{{ .Pattern }}", &grappapb.Rule{
		AllowAnonymous: {{ .AllowAnonymous }},
		RequireScope: []string{
			{{ range .RequireScope }}"{{ . }}",
			{{ end }}
		},
	})
{{ end }}
}
{{ end }}
`

// New returns a new protoc generator module
func New() *Generator {
	return &Generator{
		ModuleBase: new(pgs.ModuleBase),
	}
}

// Name returns the generator module name
func (m *Generator) Name() string {
	return "grappa"
}

// InitContext initialises the generator module context
func (m *Generator) InitContext(c pgs.BuildContext) {
	m.ModuleBase.InitContext(c)
	m.ctx = pgsgo.InitContext(c.Parameters())

	m.tpl = template.Must(template.New("grappa").Parse(templateStr))
}

// Execute executes the generator module
func (m *Generator) Execute(targets map[string]pgs.File, pkgs map[string]pgs.Package) []pgs.Artifact {
	for _, f := range targets {
		if fd, ok := m.describeFile(f); ok {
			n := m.ctx.OutputPath(f).SetExt(".grappa.go")
			m.AddGeneratorTemplateFile(n.String(), m.tpl, &fd)
		}
	}

	return m.Artifacts()
}

func (m *Generator) describeFile(f pgs.File) (file, bool) {
	fd := file{
		InputPath: f.InputPath().String(),
		Package:   string(m.ctx.PackageName(f)),
		Services:  []service{},
	}

	for _, s := range f.Services() {
		if sd, ok := m.describeService(s); ok {
			fd.Services = append(fd.Services, sd)
		}
	}

	return fd, len(fd.Services) > 0
}

func (m *Generator) describeService(s pgs.Service) (service, bool) {
	sd := service{
		Name:    m.ctx.Name(s).String(),
		Methods: []method{},
	}

	for _, sm := range s.Methods() {
		if md, ok := m.describeMethod(sm); ok {
			sd.Methods = append(sd.Methods, md)
		}
	}

	return sd, len(sd.Methods) > 0
}

func (m *Generator) describeMethod(me pgs.Method) (method, bool) {
	o := me.Descriptor().Options
	if !proto.HasExtension(o, grappapb.E_Rule) {
		return method{}, false
	}

	r := proto.GetExtension(o, grappapb.E_Rule).(*grappapb.Rule)

	return method{
		Pattern: methodPattern(me),
		Rule:    r,
	}, true
}

func methodPattern(m pgs.Method) string {
	e := strings.Split(m.FullyQualifiedName(), ".")
	return fmt.Sprintf("/%s/%s", strings.Join(e[1:len(e)-1], "."), e[len(e)-1])
}
