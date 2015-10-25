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
	"strings"
	"text/template"
)

var entityStruct = createTemplate("entityStruct", `
{{$pointerFields := .PointerFields}}
{{if .HasConstructor}}
func New{{.Name}}({{.ConstructorParameterList}}) *{{.Name}} {
	e := &{{.Name}}{
		{{range .Fields}}{{if .Constructor}}{{.Name}}: {{.Name}},
		{{else}}{{if $pointerFields}}{{.Name}}: new({{.Type}}),
		{{end}}{{end}}{{end}}
	}
{{else}}
func New{{.Name}}() *{{.Name}} {
	e := &{{.Name}}{}
{{end}}

	{{(print "new" .Name) | hook}}

	return e
}

func Empty{{.Name}}() *{{.Name}} {
	{{if .PointerFields}}return &{{.Name}}{
		{{range .Fields}}{{.Name}}: new({{.Type}}),
		{{end}}
	}{{else}}return &{{.Name}}{}{{end}}
}

var _ ab.Validator = &{{.Name}}{}

func (e *{{.Name}}) Validate() error {
	var err error

	{{(print "validate" .Name) | hook}}

	return err
}

func (e *{{.Name}}) GetID() string {
	return {{if .PointerFields}}*{{end}}e.{{(index .Fields .IDField).Name}}
}
`)

var entityCRUD = createTemplate("entityCRUD", `
var {{.Name}}NotFoundError = errors.New("{{.PrivateName}} not found")

const {{.PrivateName}}Fields = "{{.AllFields}}"

func select{{.Name}}FromQuery(db ab.DB, query string, args ...interface{}) ([]*{{.Name}}, error) {
	{{(print "before" .Name "Select") | hook}}

	entities := []*{{.Name}}{}

	rows, err := db.Query(query, args...)

	if err != nil {
		return entities, err
	}

	for rows.Next() {
		e := Empty{{.Name}}()
		{{.JSONFieldDeclarations}}
		if err = rows.Scan({{if not .PointerFields}}&{{end}}e.{{(index .Fields 0).Name}}{{.DatabaseQueryParams true false}}); err != nil {
			return []*{{.Name}}{}, err
		}

		{{.JSONDecodings}}

		entities = append(entities, e)
	}

	{{(print "after" .Name "Select") | hook}}

	return entities, err
}

func selectSingle{{.Name}}FromQuery(db ab.DB, query string, args ...interface{}) (*{{.Name}}, error) {
	entities, err := select{{.Name}}FromQuery(db, query, args...)
	if err != nil {
		return nil, err
	}

	if len(entities) > 0 {
		return entities[0], nil
	}

	return nil, nil
}
`)

var entityCRUDInsert = createTemplate("entityCRUDInsert", `
func (e *{{.Name}}) Insert(db ab.DB) error {
	{{(print "before" .Name "Insert") | hook}}

	{{.JSONFieldDeclarations}}
	{{.JSONEncodings}}
	err := db.QueryRow("INSERT INTO \"{{.TableName}}\"({{.DatabaseFieldList}}) VALUES({{.DatabaseInsertPlaceholders}}) RETURNING {{(index .Fields 0).DatabaseName}}"{{.DatabaseQueryParams false false}}).Scan({{if not .PointerFields}}&{{end}}e.{{(index .Fields 0).Name}})

	{{(print "after" .Name "Insert") | hook}}

	return err
}
`)

var entityCRUDUpdate = createTemplate("entityCRUDUpdate", `
func (e *{{.Name}}) Update(db ab.DB) error {
	{{(print "before" .Name "Update") | hook}}

	{{.JSONFieldDeclarations}}
	{{.JSONEncodings}}
	result, err := db.Exec("UPDATE \"{{.TableName}}\" SET {{.DatabaseUpdatePlaceholders}} WHERE {{(index .Fields 0).DatabaseName}} = ${{.DatabaseFields}}"{{.DatabaseQueryParams false true}})
	if err != nil {
		return err
	}

	aff, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if aff != 1 {
		return {{.Name}}NotFoundError
	}

	{{(print "after" .Name "Update") | hook}}

	return nil
}
`)

var entityCRUDDelete = createTemplate("entityCRUDDelete", `
func (e *{{.Name}}) Delete(db ab.DB) error {
	{{(print "before" .Name "Delete") | hook}}

	res, err := db.Exec("DELETE FROM \"{{.TableName}}\" WHERE {{(index .Fields 0).DatabaseName}} = $1", e.{{(index .Fields 0).Name}})
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff != 1 {
		return {{.Name}}NotFoundError
	}

	{{(print "after" .Name "Delete") | hook}}

	return nil
}
`)

var entityCRUDLoad = createTemplate("entityCRUDLoad", `
func Load{{.Name}}(db ab.DB, {{(index .Fields 0).Name}} {{(index .Fields 0).Type}}) (*{{.Name}}, error) {
	{{(print "before" .Name "Load") | hook}}

	e, err := selectSingle{{.Name}}FromQuery(db, "SELECT "+{{.PrivateName}}Fields+" FROM \"{{.TableName}}\" {{.TableAlias}} WHERE {{.TableAlias}}.{{(index .Fields 0).DatabaseName}} = $1", {{(index .Fields 0).Name}})

	{{(print "after" .Name "Load") | hook}}

	return e, err
}

func LoadAll{{.Name}}(db ab.DB, start, limit int) ([]*{{.Name}}, error) {
	{{(print "before" .Name "LoadAll") | hook}}

	entities, err := select{{.Name}}FromQuery(db, "SELECT "+{{.PrivateName}}Fields+" FROM \"{{.TableName}}\" {{.TableAlias}} ORDER BY {{(index .Fields 0).Name}} DESC LIMIT $1 OFFSET $2", limit, start)

	{{(print "after" .Name "LoadAll") | hook}}

	return entities, err
}
`)

var entityService = createTemplate("entityService", `

{{if .Service.Struct}}
type {{.Service.StructName}} struct {

}
{{end}}

func (s *{{.Service.StructName}}) Register(h *hitch.Hitch) error {
	var err error

	{{if .Service.List}}
	listMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{if .Service.Post}}
	postMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{if .Service.Get}}
	getMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{if .Service.Put}}
	putMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{if and .Service.Patch .Entity.PointerFields}}
	patchMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{if .Service.Delete}}
	deleteMiddlewares := []func(http.Handler) http.Handler{}
	{{end}}

	{{(print "before" .Service.StructName "Register") | hook}}

	if err != nil {
		return err
	}

	{{if .Service.List}}
	h.Get("/api/{{.Entity.PrivateName}}", s.{{.Entity.PrivateName}}ListHandler(), listMiddlewares...)
	{{end}}

	{{if .Service.Post}}
	h.Post("/api/{{.Entity.PrivateName}}", s.{{.Entity.PrivateName}}PostHandler(), postMiddlewares...)
	{{end}}

	{{if .Service.Get}}
	h.Get("/api/{{.Entity.PrivateName}}/:id", s.{{.Entity.PrivateName}}GetHandler(), getMiddlewares...)
	{{end}}

	{{if .Service.Put}}
	h.Put("/api/{{.Entity.PrivateName}}/:id", s.{{.Entity.PrivateName}}PutHandler(), putMiddlewares...)
	{{end}}

	{{if and .Service.Patch .Entity.PointerFields}}
	h.Patch("/api/{{.Entity.PrivateName}}/:id", s.{{.Entity.PrivateName}}PatchHandler(), patchMiddlewares...)
	{{end}}

	{{if .Service.Delete}}
	h.Delete("/api/{{.Entity.PrivateName}}/:id", s.{{.Entity.PrivateName}}DeleteHandler(), deleteMiddlewares...)
	{{end}}

	{{(print "after" .Service.StructName "Register") | hook}}

	return err
}

func {{.Entity.PrivateName}}DBErrorConverter(err *pq.Error) ab.VerboseError {
	ve := ab.NewVerboseError(err.Message, err.Detail)

	{{(print "convert" .Entity.Name "DBError") | hook}}

	return ve
}

{{if .Service.List}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}ListHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := ab.GetDB(r)
		loadFunc := LoadAll{{.Entity.Name}}
		abort := false
		start := 0
		limit := 25
		if page := r.URL.Query().Get("page"); page != "" {
			pagenum, err := strconv.Atoi(page)
			ab.MaybeFail(r, http.StatusBadRequest, err)
			start = (pagenum-1) * limit
		}

		{{(print "before" .Entity.Name "ListHandler") | hook}}

		if abort {
			return
		}

		entities, err := loadFunc(db, start, limit)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))

		{{(print "after" .Entity.Name "ListHandler") | hook}}

		if abort {
			return
		}

		ab.Render(r).JSON(entities)
	})
}
{{end}}

{{if .Service.Post}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}PostHandler() http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		entity := &{{.Entity.Name}}{}
		ab.MustDecode(r, entity)

		abort := false

		{{(print .Entity.PrivateName "PostValidation") | hook}}

		if abort {
			return
		}

		if err := entity.Validate(); err != nil {
			ab.Fail(r, http.StatusBadRequest, err)
		}

		db := ab.GetDB(r)

		err := entity.Insert(db)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))

		{{(print "after" .Entity.Name "PostInsertHandler") | hook}}

		if abort {
			return
		}

		ab.Render(r).SetCode(http.StatusCreated).JSON(entity)
	})
}
{{end}}

{{if .Service.Get}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}GetHandler() http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		id := hitch.Params(r).ByName("id")
		db := ab.GetDB(r)
		abort := false
		loadFunc := Load{{.Entity.Name}}

		{{(print "before" .Entity.Name "GetHandler") | hook}}

		if abort {
			return
		}

		entity, err := loadFunc(db, id)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))
		if entity == nil {
			ab.Fail(r, http.StatusNotFound, nil)
		}

		{{(print "after" .Entity.Name "GetHandler") | hook}}

		if abort {
			return
		}

		ab.Render(r).JSON(entity)
	})
}
{{end}}

{{if .Service.Put}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}PutHandler() http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		id := hitch.Params(r).ByName("id")

		entity := &{{.Entity.Name}}{}
		ab.MustDecode(r, entity)

		if err := entity.Validate(); {{if .Entity.PointerFields}}*{{end}}entity.{{(index .Entity.Fields .Entity.URLIDField).Name}} != id || err != nil {
			ab.Fail(r, http.StatusBadRequest, err)
		}

		db := ab.GetDB(r)
		abort := false

		{{(print "before" .Entity.Name "PutUpdateHandler") | hook}}

		if abort {
			return
		}

		err := entity.Update(db)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))

		{{(print "after" .Entity.Name "PutUpdateHandler") | hook}}

		if abort {
			return
		}

		ab.Render(r).JSON(entity)
	})
}
{{end}}

{{if and .Service.Patch .Entity.PointerFields}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}PatchHandler() http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		ab.Fail(r, http.StatusNotImplemented, nil)
	})
}
{{end}}

{{if .Service.Delete}}
func (s *{{.Service.StructName}}) {{.Entity.PrivateName}}DeleteHandler() http.Handler {
	return http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
		id := hitch.Params(r).ByName("id")
		db := ab.GetDB(r)
		abort := false
		loadFunc := Load{{.Entity.Name}}

		{{(print "before" .Entity.Name "DeleteHandler") | hook}}

		if abort {
			return
		}

		entity, err := loadFunc(db, id)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))
		if entity == nil {
			ab.Fail(r, http.StatusNotFound, nil)
		}

		{{(print "inside" .Entity.Name "DeleteHandler") | hook}}

		if abort {
			return
		}

		err = entity.Delete(db)
		ab.MaybeFail(r, http.StatusInternalServerError, ab.ConvertDBError(err, {{.Entity.PrivateName}}DBErrorConverter))

		{{(print "after" .Entity.Name "DeleteHandler") | hook}}

		if abort {
			return
		}
	})
}
{{end}}
`)

var sqlTemplate = createTemplate("sqlTemplate", `
func (s *{{.Service.StructName}}) SchemaInstalled(db ab.DB) bool {
	found := ab.TableExists(db, "{{.Entity.TableName}}")

	{{(print "after" .Entity.Name "SchemaInstalled") | hook}}

	return found
}

func (s *{{.Service.StructName}}) SchemaSQL() string {
	sql := "CREATE TABLE \"{{.Entity.TableName}}\" (\n" +
	{{range .Entity.Fields}}{{if not .NoDB}}"\t\"{{.DatabaseName}}\" {{.DatabaseType}}{{if ne .DBDefault ""}} DEFAULT {{.DBDefault}}{{end}}{{if not .DBNull}} NOT NULL{{end}},\n" +
	{{end}}{{end}}"\tCONSTRAINT {{.Entity.TableName}}_pkey PRIMARY KEY ({{(index .Entity.Fields 0).DatabaseName}})\n);\n"

	{{(print "after" .Entity.Name "SchemaSQL") | hook}}

	return sql
}
`)

var entityTemplate = template.Must(template.New("entityTemplate").Parse(`package {{.Package}}
// AUTOGENERATED DO NOT EDIT
{{.Struct}}
{{.CRUD}}
{{.Service}}
{{.SQL}}
`))

func createTemplate(name, text string) *template.Template {
	t := template.New(name)
	emptyHook(t)
	t.Funcs(map[string]interface{}{
		"tag": func(tag string) string {
			return "`" + tag + "`"
		},
		"filterString": func(str string) string {
			return strings.Replace(str, "\"", "\\\"", -1)
		},
	})
	return template.Must(t.Parse(text))
}

// Tells the API to work with the current directory.
func SetDir() {
	funcs := getFunctions()
	addHooks(entityStruct, funcs)
	addHooks(entityCRUD, funcs)
	addHooks(entityCRUDInsert, funcs)
	addHooks(entityCRUDUpdate, funcs)
	addHooks(entityCRUDDelete, funcs)
	addHooks(entityCRUDLoad, funcs)
	addHooks(entityService, funcs)
	addHooks(entityTemplate, funcs)
	addHooks(sqlTemplate, funcs)
}

func init() {
	SetDir()
}
