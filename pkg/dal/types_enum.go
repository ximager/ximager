// Code generated by go-enum DO NOT EDIT.
// Version: 0.5.6
// Revision: 97611fddaa414f53713597918c5e954646cb8623
// Build Date: 2023-03-26T21:38:06Z
// Built By: goreleaser

package dal

import (
	"errors"
	"fmt"
)

const (
	// DatabasePostgresql is a Database of type postgresql.
	DatabasePostgresql Database = "postgresql"
	// DatabaseMysql is a Database of type mysql.
	DatabaseMysql Database = "mysql"
	// DatabaseSqlite3 is a Database of type sqlite3.
	DatabaseSqlite3 Database = "sqlite3"
)

var ErrInvalidDatabase = errors.New("not a valid Database")

// String implements the Stringer interface.
func (x Database) String() string {
	return string(x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x Database) IsValid() bool {
	_, err := ParseDatabase(string(x))
	return err == nil
}

var _DatabaseValue = map[string]Database{
	"postgresql": DatabasePostgresql,
	"mysql":      DatabaseMysql,
	"sqlite3":    DatabaseSqlite3,
}

// ParseDatabase attempts to convert a string to a Database.
func ParseDatabase(name string) (Database, error) {
	if x, ok := _DatabaseValue[name]; ok {
		return x, nil
	}
	return Database(""), fmt.Errorf("%s is %w", name, ErrInvalidDatabase)
}

// MustParseDatabase converts a string to a Database, and panics if is not valid.
func MustParseDatabase(name string) Database {
	val, err := ParseDatabase(name)
	if err != nil {
		panic(err)
	}
	return val
}
