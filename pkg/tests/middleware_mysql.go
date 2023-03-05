// Copyright 2023 XImager
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

package tests

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/viper"

	"github.com/ximager/ximager/pkg/dal"
)

func init() {
	err := RegisterCIDatabaseFactory("mysql", &mysqlFactory{})
	if err != nil {
		panic(err)
	}
}

type mysqlFactory struct{}

var _ Factory = &mysqlFactory{}

func (mysqlFactory) New() CIDatabase {
	return &mysqlCIDatabase{}
}

type mysqlCIDatabase struct {
	database string
}

var _ CIDatabase = &mysqlCIDatabase{}

// Init sets the default values for the database configuration in ci tests
func (d *mysqlCIDatabase) Init() error {
	db, err := sql.Open("mysql", "root:ximager@tcp(127.0.0.1:3306)/")
	if err != nil {
		return err
	}
	d.database = strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", d.database))
	if err != nil {
		return err
	}
	err = db.Close()
	if err != nil {
		return err
	}

	viper.SetDefault("database.type", "mysql")
	viper.SetDefault("database.mysql.host", "127.0.0.1")
	viper.SetDefault("database.mysql.port", "3306")
	viper.SetDefault("database.mysql.user", "root")
	viper.SetDefault("database.mysql.password", "ximager")
	viper.SetDefault("database.mysql.database", d.database)

	err = dal.Initialize()
	if err != nil {
		return err
	}
	return nil
}

// DeInit remove the database or database file for ci tests
func (d *mysqlCIDatabase) DeInit() error {
	db, err := sql.Open("mysql", "root:ximager@tcp(127.0.0.1:3306)/")
	if err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("DROP DATABASE %s", d.database))
	if err != nil {
		return err
	}
	err = db.Close()
	if err != nil {
		return err
	}
	return nil
}
