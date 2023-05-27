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

package types

// NamespaceItem represents a namespace.
type NamespaceItem struct {
	ID          uint64  `json:"id"`
	Name        string  `json:"name" validate:"required,min=2,max=20,is_valid_namespace"`
	Description *string `json:"description" validate:"max=30"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ListNamespaceRequest represents the request to list namespaces.
type ListNamespaceRequest struct {
	Pagination

	// Name query the namespace by name.
	Name *string `json:"name" query:"name"`
}

// ListNamespaceResponse represents the response to list namespaces.
type ListNamespaceResponse struct {
	Total int64           `json:"total"`
	Items []NamespaceItem `json:"items"`
}

// CreateNamespaceRequest represents the request to create a namespace.
type CreateNamespaceRequest struct {
	Name        string  `json:"name" validate:"required,min=2,max=20,is_valid_namespace"`
	Description *string `json:"description" validate:"max=30"`
}

// CreateNamespaceResponse represents the response to create a namespace.
type CreateNamespaceResponse struct {
	ID uint64 `json:"id"`
}

// GetNamespaceRequest represents the request to get a namespace.
type GetNamespaceRequest struct {
	ID uint64 `json:"id" param:"id" validate:"required,number"`
}

// GetNamespaceResponse represents the response to get a namespace.
type GetNamespaceResponse struct {
	ID          uint64  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// DeleteNamespaceRequest represents the request to delete a namespace.
type DeleteNamespaceRequest struct {
	ID uint64 `json:"id" param:"id" validate:"required,number"`
}

// PutNamespaceRequest represents the request to update a namespace.
type PutNamespaceRequest struct {
	ID uint64 `json:"id" param:"id" validate:"required,number"`

	Description *string `json:"description" validate:"max=30,min=2"`
}
