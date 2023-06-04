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

package models

import (
	"database/sql"
	"time"

	"gorm.io/plugin/soft_delete"
)

// Tag represents a tag
type Tag struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt soft_delete.DeletedAt `gorm:"softDelete:milli"`
	ID        uint64                `gorm:"primaryKey"`

	RepositoryID uint64
	ArtifactID   uint64
	Name         string

	LastPull  sql.NullTime
	PushedAt  time.Time `gorm:"autoCreateTime"`
	PullTimes uint64    `gorm:"default:0"`

	Repository *Repository
	Artifact   *Artifact
}
