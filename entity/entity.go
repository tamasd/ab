// Copyright 2015 Tamás Demeter-Haludka
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entity

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"

	"github.com/tamasd/ab/util"
)

var (
	NotFoundError             = errors.New("entity not found")
	IncompleteStructError     = errors.New("entity struct is incomplete")
	EmptyTypeError            = errors.New("type is empty")
	PointerFieldMismatchError = errors.New("the entity must contain only pointer or non-pointer fields")
)

// A map which contains basic mapping between Go types and Postgres types.
var DBTypeMap = map[string]string{
	"string":    "character varying",
	"int64":     "int8",
	"int32":     "int4",
	"int16":     "int2",
	"int":       "int",
	"float32":   "float4",
	"float64":   "float8",
	"bool":      "bool",
	"time.Time": "timestamp with time zone",
}

// Main struct to hold the entity configuration data.
type Entity struct {
	Name          string
	Comment       string // comment for the entity struct
	Fields        []EntityField
	PointerFields bool // set this true if you want to have all your fields pointers in the entity struct
	URLIDField    uint
	IDField       uint
}

func (e Entity) FormattedComment() string {
	return formatComment(e.Comment)
}

func (e Entity) HasComment() bool {
	return e.Comment != ""
}

func (e Entity) Normalized() Entity {
	return e
}

func (e Entity) TableName() string {
	return strings.ToLower(e.Name)
}

func (e Entity) TableAlias() string {
	return e.TableName()[:1]
}

func (e Entity) PrivateName() string {
	return strings.ToLower(e.Name)
}

func (e Entity) AllFields() string {
	fields := []string{}
	for _, f := range e.Fields {
		if f.NoDB {
			continue
		}
		fields = append(fields, e.TableAlias()+"."+f.DatabaseName())
	}

	return strings.Join(fields, ", ")
}

func (e Entity) ConstructorParameterList() string {
	params := []string{}
	for _, f := range e.Fields {
		if !f.Constructor {
			continue
		}

		if e.PointerFields {
			params = append(params, f.Name+" *"+f.Type)
		} else {
			params = append(params, f.Name+" "+f.Type)
		}
	}

	return strings.Join(params, ", ")
}

func (e Entity) HasConstructor() bool {
	for _, f := range e.Fields {
		if f.Constructor {
			return true
		}
	}

	return false
}

func (e Entity) DatabaseFieldList() string {
	fields := []string{}
	for _, f := range e.Fields {
		if f.NoDB {
			continue
		}
		fields = append(fields, f.DatabaseName())
	}

	return strings.Join(fields[1:], ", ")
}

func (e Entity) DatabaseFields() (l uint) {
	for _, f := range e.Fields {
		if !f.NoDB {
			l++
		}
	}

	return l
}

func (e Entity) DatabaseInsertPlaceholders() string {
	return util.GeneratePlaceholders(1, e.DatabaseFields())
}

func (e Entity) DatabaseUpdatePlaceholders() string {
	fields := []string{}

	i := 0
	for _, f := range e.Fields[1:] {
		if f.NoDB {
			continue
		}
		fields = append(fields, fmt.Sprintf("%s = $%d", f.DatabaseName(), i+1))
		i++
	}

	return strings.Join(fields, ", ")
}

func (e Entity) DatabaseQueryParams(pointer, includePrimary bool) string {
	pointerChar := ""
	if e.PointerFields && !pointer {
		pointerChar = "*"
	}
	if !e.PointerFields && pointer {
		pointerChar = "&"
	}
	jsonPointerChar := ""
	if pointer {
		jsonPointerChar = "&"
	}

	ret := ""

	for _, f := range e.Fields[1:] {
		if f.NoDB {
			continue
		}
		if f.DatabaseType() == "json" || f.DatabaseType() == "jsonb" {
			ret += ", " + jsonPointerChar + "json" + f.Name
		} else {
			ret += ", " + pointerChar + "e." + f.Name
		}
	}

	if includePrimary {
		ret += ", " + pointerChar + "e." + e.Fields[0].Name
	}

	return ret
}

func (e Entity) JSONFieldDeclarations() string {
	ret := ""

	for _, f := range e.Fields[1:] {
		if f.DatabaseType() == "json" || f.DatabaseType() == "jsonb" {
			ret += "json" + f.Name + " := \"\"\n"
		}
	}

	return ret
}

func (e Entity) JSONDecodings() string {
	ret := ""
	pointerChar := ""
	if !e.PointerFields {
		pointerChar = "&"
	}

	for _, f := range e.Fields[1:] {
		if f.DatabaseType() == "json" || f.DatabaseType() == "jsonb" {
			ret += "json.Unmarshal([]byte(json" + f.Name + "), " + pointerChar + "e." + f.Name + ")\n"
		}
	}

	return ret
}

func (e Entity) JSONEncodings() string {
	ret := ""

	for _, f := range e.Fields[1:] {
		if f.DatabaseType() == "json" || f.DatabaseType() == "jsonb" {
			ret += "bjson" + f.Name + ", _ := json.Marshal(e." + f.Name + ")\njson" + f.Name + " = string(bjson" + f.Name + ")"
		}
	}

	return ret
}

type EntityField struct {
	Name        string // Go name of the field
	Type        string // Go type of the field
	Tag         string // Go tag of the field
	Comment     string // Comment of the field
	Constructor bool   // Constructor fields will be parameters in the NewEntity() generated function
	DBName      string // Database name of the field. Optional, if empty then ToLower(Name) will be used
	DBType      string // Database type of the field. Optional, if empty then Type will be used.
	DBDefault   string // Database default value of the field.
	DBNull      bool   // Set this true if the field can be NULL
	NoDB        bool   // Don't store this field in the database
}

func (ef EntityField) FormattedComment() string {
	return formatComment(ef.Comment)
}

func (ef EntityField) HasComment() bool {
	return ef.Comment != ""
}

func (ef EntityField) DatabaseName() string {
	if ef.DBName != "" {
		return ef.DBName
	}

	return strings.ToLower(ef.Name)
}

func (ef EntityField) DatabaseType() string {
	if ef.DBType != "" {
		return ef.DBType
	}

	return ef.Type
}

type EntityService struct {
	Struct     bool   // Generate an empty service struct
	StructName string // Name of the service struct. Default is Service.
	List       bool   // Generate a listing endpoint.
	Get        bool   // Generate a GET endpoint
	Post       bool   // Generate a POST (create new) endpoint
	Put        bool   // Generate a PUT (update) endpoint
	Patch      bool   // Generate a PATCH (update) endpoint
	Delete     bool   // Generate a DELETE endpoint
}

func (es EntityService) HasEndpoints() bool {
	return es.List || es.Get || es.Post || es.Put || es.Patch || es.Delete
}

type EntityCRUD struct {
	Insert bool
	Update bool
	Delete bool
	Load   bool
}

func (ec EntityCRUD) hasCRUD() bool {
	return ec.Insert || ec.Update || ec.Delete || ec.Load
}

type EntityTemplate struct {
	Entity
	Package         string
	GenerateStruct  bool
	GenerateCRUD    EntityCRUD
	GenerateService EntityService
	GenerateSQL     bool
}

func (et EntityTemplate) GetPackage() string {
	if et.Package == "" {
		return detectPackageName()
	}

	return et.Package
}

func (et EntityTemplate) String() string {
	etd := entityTemplateData{
		Package: et.GetPackage(),
	}

	if et.GenerateStruct {
		etd.Struct = render(entityStruct, et.Entity)
	}

	if et.GenerateCRUD.hasCRUD() {
		etd.CRUD = render(entityCRUD, et.Entity)
		if et.GenerateCRUD.Insert {
			etd.CRUD += render(entityCRUDInsert, et.Entity)
		}
		if et.GenerateCRUD.Update {
			etd.CRUD += render(entityCRUDUpdate, et.Entity)
		}
		if et.GenerateCRUD.Delete {
			etd.CRUD += render(entityCRUDDelete, et.Entity)
		}
		if et.GenerateCRUD.Load {
			etd.CRUD += render(entityCRUDLoad, et.Entity)
		}
	}

	if et.GenerateService.HasEndpoints() {
		etd.Service = render(entityService, entityServiceTemplateData{
			Entity:  et.Entity,
			Service: et.GenerateService,
		})
	}

	if et.GenerateSQL {
		etd.SQL = render(sqlTemplate, entitySQLTemplateData{
			Entity:  et.Entity,
			Service: et.GenerateService,
		})
	}

	return render(entityTemplate, etd)
}

type entitySQLTemplateData struct {
	Entity  Entity
	Service EntityService
}

type entityServiceTemplateData struct {
	Entity  Entity
	Service EntityService
}

type entityTemplateData struct {
	Package string
	Struct  string
	CRUD    string
	Service string
	SQL     string
}

func detectPackageName() string {
	for _, fname := range listInterestingFiles() {
		f, err := parser.ParseFile(token.NewFileSet(), fname, nil, parser.PackageClauseOnly)
		if err != nil {
			continue
		}
		if f.Name.Name != "" {
			return f.Name.Name
		}
	}

	return ""
}

func listInterestingFiles() []string {
	files := []string{}
	matches, _ := filepath.Glob("*.go")
	for _, match := range matches {
		if strings.HasPrefix(match, ".") || strings.HasPrefix(match, "_") {
			continue
		}

		files = append(files, match)
	}

	return files
}

type Function struct {
	Name       string
	Parameters []FunctionParameter
	Returns    []FunctionParameter
}

func (f Function) String() string {
	params := []string{}
	for _, p := range f.Parameters {
		params = append(params, p.String())
	}
	returns := []string{}
	for _, r := range f.Returns {
		returns = append(returns, r.String())
	}

	prefix := ""

	if len(returns) > 0 {
		prefix = strings.Join(returns, ", ") + " = "
	}

	return prefix + f.Name + "(" + strings.Join(params, ", ") + ")"
}

type FunctionParameter struct {
	Name string
}

func (fp FunctionParameter) String() string {
	if fp.Name[0] == '_' {
		return fp.Name[1:]
	}
	return fp.Name
}

func getFunctions() []Function {
	funcs := []Function{}
	for _, file := range listInterestingFiles() {
		funcs = append(funcs, getFunctionsFromFile(file)...)
	}

	return funcs
}

func GetEntity(name string) (Entity, error) {
	for _, file := range listInterestingFiles() {
		ent, err := getEntityStructFromFile(file, name)
		if err == nil {
			return ent, nil
		}
		if err != NotFoundError {
			return Entity{}, err
		}
	}

	return Entity{}, NotFoundError
}

func getEntityStructFromFile(file, name string) (Entity, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.AllErrors)
	if err != nil {
		return Entity{}, err
	}

	filecontent, err := ioutil.ReadFile(file)
	if err != nil {
		return Entity{}, err
	}

	for _, decl := range f.Decls {
		if gdecl, ok := decl.(*ast.GenDecl); ok {
			for _, spec := range gdecl.Specs {
				if tspec, ok := spec.(*ast.TypeSpec); ok {
					if stype, ok := tspec.Type.(*ast.StructType); tspec.Name.Name == name && ok {
						return createEntityFromStruct(name, string(filecontent), stype)
					}
				}
			}
		}
	}

	return Entity{}, NotFoundError
}

func createEntityFromStruct(name, filecontent string, stype *ast.StructType) (Entity, error) {
	ent := Entity{
		Name: name,
	}

	if stype.Incomplete {
		return Entity{}, IncompleteStructError
	}

	var pointerFields *bool

	for _, field := range stype.Fields.List {
		tag := reflect.StructTag("")
		if field.Tag != nil {
			tag = reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
		}

		t := strings.TrimSpace(filecontent[field.Type.Pos()-1 : field.Type.End()])

		if t == "" {
			return Entity{}, EmptyTypeError
		}

		if pointerFields == nil {
			pointerFields = new(bool)
			*pointerFields = t[0] == '*'
		}

		if *pointerFields != (t[0] == '*') {
			return Entity{}, PointerFieldMismatchError
		}

		if *pointerFields {
			t = t[1:]
		}

		for _, n := range field.Names {
			ent.Fields = append(ent.Fields, EntityField{
				Name:        n.Name,
				Type:        t,
				Constructor: tag.Get("constructor") == "true",
				DBType:      resolveDBType(t, tag),
				DBName:      tag.Get("dbname"),
				DBDefault:   tag.Get("dbdefault"),
				DBNull:      tag.Get("dbnull") == "true",
				NoDB:        tag.Get("nodb") == "true",
			})
		}
	}

	ent.PointerFields = *pointerFields

	return ent, nil
}

func resolveDBType(t string, tag reflect.StructTag) string {
	if tt := tag.Get("dbtype"); tt != "" {
		return tt
	}

	return DBTypeMap[t]
}

func getFunctionsFromFile(file string) []Function {
	funcs := []Function{}
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.AllErrors)
	if err != nil {
		log.Println(err)
		return funcs
	}

	for _, decl := range f.Decls {
		if fdecl, ok := decl.(*ast.FuncDecl); ok {
			if fdecl.Recv != nil {
				continue
			}

			fnc := Function{
				Name:       fdecl.Name.Name,
				Parameters: []FunctionParameter{},
				Returns:    []FunctionParameter{},
			}

			for _, field := range fdecl.Type.Params.List {
				for _, name := range field.Names {
					fnc.Parameters = append(fnc.Parameters, FunctionParameter{
						Name: name.Name,
					})
				}
			}

			if fdecl.Type.Results != nil && fdecl.Type.Results.List != nil {
				for _, field := range fdecl.Type.Results.List {
					if field != nil {
						for _, name := range field.Names {
							if name != nil && name.Name != "" {
								fnc.Returns = append(fnc.Returns, FunctionParameter{
									Name: name.Name,
								})
							}
						}
					}
				}
			}

			funcs = append(funcs, fnc)
		}
	}

	return funcs
}

func addHooks(t *template.Template, funcs []Function) *template.Template {
	var m template.FuncMap = template.FuncMap{
		"hook": func(name string) string {
			for _, f := range funcs {
				if f.Name == name {
					return f.String()
				}
			}

			return "// HOOK: " + name + "()"
		},
	}
	return t.Funcs(m)
}

func emptyHook(t *template.Template) *template.Template {
	var m template.FuncMap = template.FuncMap{
		"hook": func(name string) string {
			return name
		},
	}

	return t.Funcs(m)
}

func render(t *template.Template, v interface{}) string {
	buf := bytes.NewBuffer(nil)
	if err := t.Execute(buf, v); err != nil {
		log.Println(err)
		return ""
	}

	return string(buf.Bytes())
}

func formatComment(s string) string {
	lines := []string{}
	for _, line := range strings.Split(s, "\n") {
		lines = append(lines, "// "+line)
	}

	return strings.Join(lines, "\n")
}
