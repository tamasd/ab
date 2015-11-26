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
	"database/sql"
	"net"
	"net/http"
	"time"

	"github.com/lib/pq"
	"github.com/nbio/httpcontext"
)

const dbConnectionKey = "abdb"

// An abstraction over *sql.DB and *sql.Tx
type DB interface {
	Exec(string, ...interface{}) (sql.Result, error)
	Query(string, ...interface{}) (*sql.Rows, error)
	QueryRow(string, ...interface{}) *sql.Row
	Prepare(string) (*sql.Stmt, error)
}

// Gets the DB from the request context.
func GetDB(r *http.Request) DB {
	return httpcontext.Get(r, dbConnectionKey).(DB)
}

// Retrieves or creates a transaction from the request context.
//
// This function does not support nested transactions. The user of this function does not need to commit or roll back the transaction, it will happen automatically.
func GetTransaction(r *http.Request) DB {
	db := GetDB(r)
	if tx, ok := db.(*sql.Tx); ok {
		return tx
	}

	dbconn := db.(*sql.DB)

	tx, err := dbconn.Begin()
	if err != nil {
		LogVerbose(r).Println(err)
		return nil
	}

	httpcontext.Set(r, dbConnectionKey, tx)

	return tx
}

func connectToDB(connectString string) (*sql.DB, error) {
	conn, err := sql.Open("postgres", connectString)
	if err != nil {
		return nil, err
	}

	_, err = conn.Exec(`
		CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;
		CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
		SET search_path = public, pg_catalog;
	`)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func retryDBConn(connectString string, tries uint) *sql.DB {
	conn, err := connectToDB(connectString)
	if err != nil {
		if operr, ok := err.(*net.OpError); ok && operr.Op == "dial" && tries > 0 {
			<-time.After(time.Second)
			return retryDBConn(connectString, tries-1)
		}
		panic(err)
	}

	return conn
}

// A middleware to manage the database connection. Currently only PostgreSQL is supported.
//
// This middleware is automatically added to the server with PetBunny if the server has a connect string.
// It also automatically commits the transaction (if there's any), or rolls it back on panic.
func DBMiddleware(connectString string, maxIdleConnections, maxOpenConnections int) (func(http.Handler) http.Handler, *sql.DB) {
	conn := retryDBConn(connectString, 10)

	conn.SetMaxIdleConns(maxIdleConnections)
	conn.SetMaxOpenConns(maxOpenConnections)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpcontext.Set(r, dbConnectionKey, conn)

			defer func() {
				// If something bad happened, let's roll back the transaction
				if dbtx, ok := GetDB(r).(*sql.Tx); ok {
					dbtx.Rollback()
				}
			}()

			next.ServeHTTP(w, r)

			// Check if there's a transaction, and commit it
			if dbtx, ok := GetDB(r).(*sql.Tx); ok {
				dbtx.Commit()
			}
		})
	}, conn
}

// Checks if a table exists in the database.
func TableExists(db DB, table string) bool {
	var found bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = $1 AND c.relkind = 'r');", table).Scan(&found)
	if err != nil {
		panic(err)
	}

	return found
}

// Converts an error with conv if that error is *pq.Error.
//
// Useful when processing database errors (e.g. constraint violations), so the user can get a nice error message.
func ConvertDBError(err error, conv func(*pq.Error) VerboseError) error {
	if err == nil {
		return nil
	}

	if perr, ok := err.(*pq.Error); ok {
		return conv(perr)
	}

	return err
}
