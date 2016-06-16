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

package ab

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/tamasd/ab/util"
)

// Interface for the entities.
//
// Types implementing the Entity interface are expected to be pointers to structs.
type Entity interface {
	GetID() string
}

type EntityInserter interface {
	Insert(DB) error
}

type EntityUpdater interface {
	Update(DB) error
}

type EntityDeleter interface {
	Delete(DB) error
}

// Maps Go types to PostgreSQL types
var EntityDBTypeMap = map[string]string{
	"string":  "character varying",
	"int64":   "int8",
	"int32":   "int4",
	"int16":   "int2",
	"int":     "int",
	"float32": "float4",
	"float64": "float8",
	"bool":    "bool",
	"Time":    "timestamp with time zone",
	"struct":  "jsonb",
}

type EntityDelegate interface {
	Validate(e Entity) error
	AlterSQL(string) string
}

type entityData struct {
	Type         reflect.Type
	FieldList    string
	Delegate     EntityDelegate
	FieldIndexes struct {
		PrimaryKey []int
		Field      []int
		NoDefaults []int
		Defaults   []int
		JSON       []int
	}
	Queries struct {
		Select string
		Insert string
		Update string
		Delete string
	}
}

type EntityController struct {
	db          DB
	entityTypes map[string]*entityData
}

func NewEntityController(db DB) *EntityController {
	return &EntityController{
		db:          db,
		entityTypes: make(map[string]*entityData),
	}
}

func (ec *EntityController) getData(e Entity) (string, *entityData) {
	if e == nil {
		panic("entity is nil")
	}

	name := ec.Type(e)
	if d, ok := ec.entityTypes[name]; ok {
		return name, d
	}
	panic("entity type " + name + " is not added to the controller")
}

func (ec *EntityController) Type(e Entity) string {
	return strings.ToLower(reflect.TypeOf(e).Elem().Name())
}

func (ec *EntityController) Add(e Entity, delegate EntityDelegate) *EntityController {
	if reflect.TypeOf(e).Kind() != reflect.Ptr {
		panic("entity must be a pointer")
	}

	entityType := reflect.TypeOf(e).Elem()
	name := ec.Type(e)

	if _, exists := ec.entityTypes[name]; exists {
		panic("entity is already registered")
	}

	ec.entityTypes[name] = &entityData{
		Type:     entityType,
		Delegate: delegate,
	}

	prefix := ec.TableAbbrev(name)

	fieldlist := make([]string, entityType.NumField())
	for i := 0; i < len(fieldlist); i++ {
		fieldlist[i] = prefix + "." + strings.ToLower(entityType.Field(i).Name)
	}
	ec.entityTypes[name].FieldList = strings.Join(fieldlist, ", ")

	ec.entityTypes[name].FieldIndexes.PrimaryKey, ec.entityTypes[name].FieldIndexes.Field, ec.entityTypes[name].FieldIndexes.NoDefaults, ec.entityTypes[name].FieldIndexes.Defaults, ec.entityTypes[name].FieldIndexes.JSON = ec.getEntityFieldIndexes(entityType)

	ec.entityTypes[name].Queries.Select = ec.createSelectQuery(name, prefix, entityType)
	ec.entityTypes[name].Queries.Insert = ec.createInsertQuery(name, entityType)
	ec.entityTypes[name].Queries.Update = ec.createUpdateQuery(name, entityType)
	ec.entityTypes[name].Queries.Delete = ec.createDeleteQuery(name, entityType)

	return ec
}

func (ec *EntityController) TableAbbrev(name string) string {
	return strings.ToLower(ec.entityTypes[name].Type.Name()[:1])
}

func (ec *EntityController) FieldList(name string) string {
	return ec.entityTypes[name].FieldList
}

func (ec *EntityController) createSelectQuery(name, prefix string, entityType reflect.Type) string {
	sql := "SELECT " + ec.entityTypes[name].FieldList + " FROM \"" + name + "\" " + prefix + " WHERE "
	conds := make([]string, len(ec.entityTypes[name].FieldIndexes.PrimaryKey))
	for i, f := range ec.entityTypes[name].FieldIndexes.PrimaryKey {
		conds[i] = fmt.Sprintf("\"%s\" = $%d", strings.ToLower(entityType.Field(f).Name), i+1)
	}

	sql += strings.Join(conds, " AND ")

	return sql
}

func (ec *EntityController) createInsertQuery(name string, entityType reflect.Type) string {
	fieldlist := make([]string, len(ec.entityTypes[name].FieldIndexes.NoDefaults))
	for i, f := range ec.entityTypes[name].FieldIndexes.NoDefaults {
		fieldlist[i] = "\"" + strings.ToLower(entityType.Field(f).Name) + "\""
	}
	placeholders := util.GeneratePlaceholders(1, uint(len(ec.entityTypes[name].FieldIndexes.NoDefaults)+1))
	returning := make([]string, len(ec.entityTypes[name].FieldIndexes.Defaults))
	for i, f := range ec.entityTypes[name].FieldIndexes.Defaults {
		returning[i] = "\"" + strings.ToLower(entityType.Field(f).Name) + "\""
	}
	return "INSERT INTO \"" + name + "\"(" + strings.Join(fieldlist, ", ") + ") VALUES(" + placeholders + ") RETURNING " + strings.Join(returning, ", ")
}

func (ec *EntityController) createUpdateQuery(name string, entityType reflect.Type) string {
	placeholder := 1

	fields := make([]string, len(ec.entityTypes[name].FieldIndexes.Field))
	for i, f := range ec.entityTypes[name].FieldIndexes.Field {
		fields[i] = fmt.Sprintf("\"%s\" = $%d", strings.ToLower(entityType.Field(f).Name), placeholder)
		placeholder++
	}

	conds := make([]string, len(ec.entityTypes[name].FieldIndexes.PrimaryKey))
	for i, f := range ec.entityTypes[name].FieldIndexes.PrimaryKey {
		conds[i] = fmt.Sprintf("\"%s\" = $%d", strings.ToLower(entityType.Field(f).Name), placeholder)
		placeholder++
	}

	return "UPDATE \"" + name + "\" SET " + strings.Join(fields, ", ") + " WHERE " + strings.Join(conds, " AND ")
}

func (ec *EntityController) createDeleteQuery(name string, entityType reflect.Type) string {
	sql := "DELETE FROM \"" + name + "\" WHERE "
	conds := make([]string, len(ec.entityTypes[name].FieldIndexes.PrimaryKey))
	for i, f := range ec.entityTypes[name].FieldIndexes.PrimaryKey {
		conds[i] = fmt.Sprintf("\"%s\" = $%d", strings.ToLower(entityType.Field(f).Name), i+1)
	}

	sql += strings.Join(conds, " AND ")

	return sql
}

type entityForeignKey struct {
	table     string
	reffields []string
	fields    []string
	onUpdate  string
	onDelete  string
}

// syntax: table.field1.field2,field1.field2,cascade,cascade
func parseForeignKey(decl string) entityForeignKey {
	fkey := entityForeignKey{}
	parts := strings.Split(decl, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}

	firstPart := strings.Split(parts[0], ".")
	if len(firstPart) < 2 {
		panic("invalid foreign key syntax")
	}
	fkey.table = firstPart[0]
	fkey.reffields = firstPart[1:]

	if len(parts) > 1 {
		fkey.fields = strings.Split(parts[1], ".")
	} else {
		fkey.fields = fkey.reffields
	}

	if len(parts) > 2 {
		fkey.onUpdate = strings.ToUpper(parts[2])
	} else {
		fkey.onUpdate = "CASCADE"
	}

	if len(parts) > 3 {
		fkey.onDelete = strings.ToUpper(parts[3])
	} else {
		fkey.onDelete = "CASCADE"
	}

	return fkey
}

func (ec *EntityController) SchemaSQL(e Entity) string {
	name, data := ec.getData(e)

	primaryKey := []string{}
	foreignKey := []entityForeignKey{}
	sql := "CREATE TABLE \"" + name + "\"(\n"

	numField := data.Type.NumField()
	for i := 0; i < numField; i++ {
		field := data.Type.Field(i)
		fieldName := strings.ToLower(field.Name)
		sqlType := ec.getDBType(field)
		fieldDefault := ""
		if def := field.Tag.Get("dbdefault"); def != "" {
			fieldDefault = " DEFAULT " + def
		}

		if field.Tag.Get("dbprimary") == "true" {
			primaryKey = append(primaryKey, fieldName)
		}

		if fkdef := field.Tag.Get("dbforeign"); fkdef != "" {
			fk := parseForeignKey(fkdef)
			foreignKey = append(foreignKey, fk)
		}

		sql += "\t\"" + fieldName + "\" " + sqlType + " NOT NULL" + fieldDefault + ",\n"
	}

	if len(primaryKey) == 0 {
		primaryKey = append(primaryKey, strings.ToLower(data.Type.Field(0).Name))
	}

	sql += "\n"

	for _, fkey := range foreignKey {
		fkname := name + "_" + strings.Join(fkey.reffields, "_") + "_fkey"
		fkeyfields := make([]string, len(fkey.fields))
		for i, f := range fkey.fields {
			fkeyfields[i] = "\"" + f + "\""
		}
		fkeyreffields := make([]string, len(fkey.reffields))
		for i, f := range fkey.reffields {
			fkeyreffields[i] = "\"" + f + "\""
		}
		sql += "\tCONSTRAINT " + fkname + " " +
			"FOREIGN KEY (" + strings.Join(fkeyfields, ", ") + ") " +
			"REFERENCES \"" + fkey.table + "\"(" + strings.Join(fkeyreffields, ", ") + ") " +
			"MATCH SIMPLE ON UPDATE " + fkey.onUpdate + " ON DELETE " + fkey.onDelete + ",\n"
	}

	for i, k := range primaryKey {
		primaryKey[i] = "\"" + k + "\""
	}
	sql += "\tCONSTRAINT " + name + "_pkey PRIMARY KEY (" + strings.Join(primaryKey, ", ") + ")\n"

	sql += ");\n"

	if data.Delegate != nil {
		sql = data.Delegate.AlterSQL(sql)
	}

	return sql
}

func (ec *EntityController) getDBType(field reflect.StructField) string {
	if sqlType := field.Tag.Get("dbtype"); sqlType != "" {
		return sqlType
	}
	if sqlType := EntityDBTypeMap[field.Type.Name()]; sqlType != "" {
		return sqlType
	}
	if sqlType := EntityDBTypeMap[field.Type.Kind().String()]; sqlType != "" {
		return sqlType
	}

	return ""
}

func (ec *EntityController) getEntityFieldIndexes(entityType reflect.Type) ([]int, []int, []int, []int, []int) {
	primaries := []int{}
	fields := []int{}
	nodefaults := []int{}
	defaults := []int{}
	jsons := []int{}

	numField := entityType.NumField()
	for i := 0; i < numField; i++ {
		field := entityType.Field(i)
		if field.Tag.Get("dbprimary") == "true" {
			primaries = append(primaries, i)
		} else {
			fields = append(fields, i)
		}
		if field.Tag.Get("dbdefault") == "" {
			nodefaults = append(nodefaults, i)
		} else {
			defaults = append(defaults, i)
		}
		if dbtype := ec.getDBType(field); dbtype == "jsonb" || dbtype == "json" {
			jsons = append(jsons, i)
		}
	}

	if len(primaries) == 0 {
		primaries, fields = fields[:1], fields[1:]
	}

	return primaries, fields, nodefaults, defaults, jsons
}

func (ec *EntityController) Empty(name string) Entity {
	return reflect.New(ec.entityTypes[name].Type).Interface().(Entity)
}

func (ec *EntityController) Load(db DB, entityType string, keys ...interface{}) (Entity, error) {
	entities, err := ec.LoadFromQuery(db, entityType, ec.entityTypes[entityType].Queries.Select, keys...)
	if err != nil {
		return nil, err
	}

	if len(entities) != 1 {
		return nil, nil
	}

	return entities[0], nil
}

func (ec *EntityController) LoadFromQuery(db DB, entityType string, query string, args ...interface{}) ([]Entity, error) {
	if db == nil {
		db = ec.db
	}
	data := ec.entityTypes[entityType]
	numField := data.Type.NumField()
	entities := []Entity{}
	rows, err := db.Query(query, args...)
	if err != nil {
		return []Entity{}, err
	}
	for rows.Next() {
		e := ec.Empty(entityType)
		v := reflect.ValueOf(e).Elem()
		pointers := make([]interface{}, numField)
		for i := 0; i < numField; i++ {
			pointers[i] = ec.scanDataPointer(v, data, i)
		}
		if err := rows.Scan(pointers...); err != nil {
			return []Entity{}, err
		}

		if err := ec.fixJSONStruct(v, data, pointers); err != nil {
			return []Entity{}, err
		}

		entities = append(entities, e)
	}

	return entities, nil
}

func (ec *EntityController) Insert(db DB, e Entity) error {
	if db == nil {
		db = ec.db
	}
	if ei, ok := e.(EntityInserter); ok {
		return ei.Insert(db)
	}
	_, data := ec.getData(e)

	v := reflect.ValueOf(e).Elem()
	args := make([]interface{}, len(data.FieldIndexes.NoDefaults))
	for i, f := range data.FieldIndexes.NoDefaults {
		args[i] = ec.fieldData(v, data, f)
	}
	returning := make([]interface{}, len(data.FieldIndexes.Defaults))
	for i, f := range data.FieldIndexes.Defaults {
		returning[i] = ec.scanDataPointer(v, data, f)
	}

	return db.QueryRow(data.Queries.Insert, args...).Scan(returning...)
}

func (ec *EntityController) Update(db DB, e Entity) error {
	if db == nil {
		db = ec.db
	}
	if eu, ok := e.(EntityUpdater); ok {
		return eu.Update(db)
	}
	_, data := ec.getData(e)
	v := reflect.ValueOf(e).Elem()
	fields := make([]interface{}, len(data.FieldIndexes.Field))
	for i, f := range data.FieldIndexes.Field {
		fields[i] = ec.fieldData(v, data, f)
	}
	pkey := make([]interface{}, len(data.FieldIndexes.PrimaryKey))
	for i, f := range data.FieldIndexes.PrimaryKey {
		pkey[i] = ec.scanDataPointer(v, data, f)
	}

	_, err := db.Exec(data.Queries.Update, append(fields, pkey...)...)
	return err
}

func (ec *EntityController) Delete(db DB, e Entity) error {
	if db == nil {
		db = ec.db
	}
	if ed, ok := e.(EntityDeleter); ok {
		return ed.Delete(db)
	}
	_, data := ec.getData(e)
	v := reflect.ValueOf(e).Elem()
	pkey := make([]interface{}, len(data.FieldIndexes.PrimaryKey))
	for i, f := range data.FieldIndexes.PrimaryKey {
		pkey[i] = ec.fieldData(v, data, f)
	}

	_, err := db.Exec(data.Queries.Delete, pkey...)
	return err
}

func (ec *EntityController) Validate(e Entity) error {
	if v, ok := e.(Validator); ok {
		if err := v.Validate(); err != nil {
			return err
		}
	}

	_, data := ec.getData(e)
	if data.Delegate != nil {
		return data.Delegate.Validate(e)
	}

	return nil
}

func (ec *EntityController) fixJSONStruct(v reflect.Value, data *entityData, pointers []interface{}) error {
	for _, i := range data.FieldIndexes.JSON {
		data := []byte(*(pointers[i].(*string)))
		field := v.Field(i).Addr().Interface()
		if err := json.Unmarshal(data, field); err != nil {
			return err
		}
	}

	return nil
}

func (ec *EntityController) scanDataPointer(v reflect.Value, data *entityData, i int) interface{} {
	if ec.isJSONField(data, i) {
		return new(string)
	}

	return v.Field(i).Addr().Interface()
}

func (ec *EntityController) fieldData(v reflect.Value, data *entityData, i int) interface{} {
	iface := v.Field(i).Interface()
	if ec.isJSONField(data, i) {
		js, _ := json.Marshal(iface)
		return js
	}

	return iface
}

func (ec *EntityController) isJSONField(data *entityData, i int) bool {
	for _, id := range data.FieldIndexes.JSON {
		if id == i {
			return true
		}
	}

	return false
}
