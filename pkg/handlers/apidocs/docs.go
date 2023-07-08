// Code generated by swaggo/swag. DO NOT EDIT.

package apidocs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "XImager",
            "url": "https://github.com/ximager/ximager"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/namespaces/": {
            "get": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Namespace"
                ],
                "summary": "List namespace",
                "parameters": [
                    {
                        "maximum": 100,
                        "minimum": 10,
                        "type": "integer",
                        "default": 10,
                        "description": "limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "minimum": 0,
                        "type": "integer",
                        "default": 0,
                        "description": "last",
                        "name": "last",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "search namespace with name",
                        "name": "name",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "allOf": [
                                {
                                    "$ref": "#/definitions/types.CommonList"
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {
                                                "$ref": "#/definitions/types.NamespaceItem"
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            },
            "post": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Namespace"
                ],
                "summary": "Create namespace",
                "parameters": [
                    {
                        "description": "Namespace object",
                        "name": "message",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/types.PostNamespaceRequest"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/types.PostNamespaceResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            }
        },
        "/namespaces/{id}": {
            "get": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Namespace"
                ],
                "summary": "Get namespace",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Namespace ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/types.GetNamespaceResponse"
                        }
                    }
                }
            },
            "put": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Namespace"
                ],
                "summary": "Update namespace",
                "parameters": [
                    {
                        "description": "Namespace object",
                        "name": "message",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/types.PutNamespaceRequestSwagger"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/types.GetNamespaceResponse"
                        }
                    }
                }
            },
            "delete": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Namespace"
                ],
                "summary": "Delete namespace",
                "responses": {
                    "204": {
                        "description": "No Content"
                    }
                }
            }
        },
        "/namespaces/{namespace}/repositories/": {
            "get": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Repository"
                ],
                "summary": "List repository",
                "parameters": [
                    {
                        "maximum": 100,
                        "minimum": 10,
                        "type": "integer",
                        "default": 10,
                        "description": "limit",
                        "name": "limit",
                        "in": "query",
                        "required": true
                    },
                    {
                        "minimum": 0,
                        "type": "integer",
                        "default": 0,
                        "description": "last",
                        "name": "last",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "namespace",
                        "name": "namespace",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "allOf": [
                                {
                                    "$ref": "#/definitions/types.CommonList"
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {
                                                "$ref": "#/definitions/types.RepositoryItem"
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            },
            "post": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Repository"
                ],
                "summary": "Create repository",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Namespace name",
                        "name": "namespace",
                        "in": "path",
                        "required": true
                    },
                    {
                        "description": "Repository object",
                        "name": "message",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/types.PostRepositoryRequestSwagger"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/types.PostRepositoryResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            }
        },
        "/namespaces/{namespace}/repositories/{id}": {
            "get": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Repository"
                ],
                "summary": "Get repository",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Namespace",
                        "name": "namespace",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/types.RepositoryItem"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            },
            "put": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Repository"
                ],
                "summary": "Update repository",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Namespace name",
                        "name": "namespace",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Repository id",
                        "name": "id",
                        "in": "path",
                        "required": true
                    },
                    {
                        "description": "Repository object",
                        "name": "message",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/types.PutRepositoryRequestSwagger"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/types.PutRepositoryResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            },
            "delete": {
                "security": [
                    {
                        "BasicAuth": []
                    }
                ],
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Repository"
                ],
                "summary": "Delete repository",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Namespace",
                        "name": "namespace",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Repository ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "No Content"
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/xerrors.ErrCode"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "enums.Visibility": {
            "type": "string",
            "enum": [
                "private",
                "public"
            ],
            "x-enum-varnames": [
                "VisibilityPrivate",
                "VisibilityPublic"
            ]
        },
        "types.CommonList": {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {}
                },
                "total": {
                    "type": "integer",
                    "example": 1
                }
            }
        },
        "types.GetNamespaceResponse": {
            "type": "object",
            "properties": {
                "created_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                },
                "description": {
                    "type": "string",
                    "example": "i am just description"
                },
                "id": {
                    "type": "integer",
                    "example": 1
                },
                "name": {
                    "type": "string",
                    "example": "test"
                },
                "repository_count": {
                    "type": "integer",
                    "example": 10
                },
                "size": {
                    "type": "integer",
                    "example": 10000
                },
                "size_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "tag_count": {
                    "type": "integer",
                    "example": 10
                },
                "tag_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "updated_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                }
            }
        },
        "types.NamespaceItem": {
            "type": "object",
            "properties": {
                "created_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                },
                "description": {
                    "type": "string",
                    "example": "i am just description"
                },
                "id": {
                    "type": "integer",
                    "example": 1
                },
                "name": {
                    "type": "string",
                    "example": "test"
                },
                "repository_count": {
                    "type": "integer",
                    "example": 10
                },
                "size": {
                    "type": "integer",
                    "example": 10000
                },
                "size_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "tag_count": {
                    "type": "integer",
                    "example": 10
                },
                "updated_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                }
            }
        },
        "types.PostNamespaceRequest": {
            "type": "object",
            "required": [
                "name"
            ],
            "properties": {
                "description": {
                    "type": "string",
                    "maxLength": 30,
                    "example": "i am just description"
                },
                "name": {
                    "type": "string",
                    "maxLength": 20,
                    "minLength": 2,
                    "example": "test"
                },
                "size_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "tag_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "visibility": {
                    "allOf": [
                        {
                            "$ref": "#/definitions/enums.Visibility"
                        }
                    ],
                    "example": "public"
                }
            }
        },
        "types.PostNamespaceResponse": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "example": 21911
                }
            }
        },
        "types.PostRepositoryRequestSwagger": {
            "type": "object",
            "required": [
                "name"
            ],
            "properties": {
                "name": {
                    "type": "string",
                    "example": "test"
                }
            }
        },
        "types.PostRepositoryResponse": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "example": 21911
                }
            }
        },
        "types.PutNamespaceRequestSwagger": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "maxLength": 30,
                    "example": "i am just description"
                },
                "size_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "tag_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "visibility": {
                    "allOf": [
                        {
                            "$ref": "#/definitions/enums.Visibility"
                        }
                    ],
                    "example": "public"
                }
            }
        },
        "types.PutRepositoryRequestSwagger": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "maxLength": 300,
                    "example": "i am just description"
                },
                "overview": {
                    "type": "string",
                    "maxLength": 3000,
                    "example": "i am just overview"
                }
            }
        },
        "types.PutRepositoryResponse": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "example": 21911
                }
            }
        },
        "types.RepositoryItem": {
            "type": "object",
            "properties": {
                "created_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                },
                "id": {
                    "type": "integer",
                    "example": 1
                },
                "name": {
                    "type": "string",
                    "example": "busybox"
                },
                "size": {
                    "type": "integer",
                    "example": 10000
                },
                "size_limit": {
                    "type": "integer",
                    "example": 10000
                },
                "tag_count": {
                    "type": "integer",
                    "example": 100
                },
                "tag_limit": {
                    "type": "integer",
                    "example": 1000
                },
                "updated_at": {
                    "type": "string",
                    "example": "2006-01-02 15:04:05"
                }
            }
        },
        "xerrors.ErrCode": {
            "type": "object",
            "properties": {
                "code": {
                    "description": "Code provides a unique, string key, often capitalized with\nunderscores, to identify the error code. This value is used as the\nkeyed value when serializing api errors.",
                    "type": "string",
                    "example": "UNAUTHORIZED"
                },
                "description": {
                    "description": "Description provides a complete account of the errors purpose, suitable\nfor use in documentation.",
                    "type": "string",
                    "example": "The access controller was unable to authenticate the client. Often this will be accompanied by a Www-Authenticate HTTP response header indicating how to authenticate."
                },
                "httpStatusCode": {
                    "description": "HTTPStatusCode provides the http status code that is associated with\nthis error condition.",
                    "type": "integer",
                    "example": 401
                },
                "title": {
                    "description": "Title is a short, human readable description of the error condition\nincluded in API responses.",
                    "type": "string",
                    "example": "authentication required"
                }
            }
        }
    },
    "securityDefinitions": {
        "BasicAuth": {
            "type": "basic"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "XImager API",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
