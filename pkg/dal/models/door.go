// Copyright 2025 sigma
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

package models

import (
	"gorm.io/plugin/soft_delete"

	"github.com/go-sigma/sigma/pkg/types/enums"
)

// AuthRule ...
type AuthRule struct {
	CreatedAt int64                 `gorm:"autoCreateTime:milli"`
	UpdatedAt int64                 `gorm:"autoUpdateTime:milli"`
	DeletedAt soft_delete.DeletedAt `gorm:"softDelete:milli"`
	ID        string                `gorm:"column:id,maxsize:26,primaryKey"`

	Role     enums.AuthRole     `gorm:"column:role"`
	Resource enums.AuthResource `gorm:"column:resource"`
	Action   enums.AuthAction   `gorm:"column:action"`
	Effect   enums.AuthEffect   `gorm:"column:effect"`
}

// AuthRole ...
type AuthRole struct {
	CreatedAt int64                 `gorm:"autoCreateTime:milli"`
	UpdatedAt int64                 `gorm:"autoUpdateTime:milli"`
	DeletedAt soft_delete.DeletedAt `gorm:"softDelete:milli"`
	ID        string                `gorm:"column:ulid,maxsize:26,primaryKey"`

	RoleID string   `gorm:"column:role_id"`
	Role   AuthRule `gorm:"foreignKey:RoleID"`

	ScopeValue string          `gorm:"column:scope_value"`
	ScopeType  enums.AuthScope `gorm:"column:scope_type"`

	UserID string `gorm:"column:user_id"`
	User   User   `gorm:"foreignKey:UserID"`
}
