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

package user

import (
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"

	rhandlers "github.com/ximager/ximager/pkg/handlers"
	"github.com/ximager/ximager/pkg/middlewares"
	"github.com/ximager/ximager/pkg/utils"
	"github.com/ximager/ximager/pkg/utils/password"
	"github.com/ximager/ximager/pkg/utils/token"
)

// Handlers is the interface for the tag handlers
type Handlers interface {
	// Login handles the login request
	Login(c echo.Context) error
	// Logout handles the logout request
	Logout(c echo.Context) error
	// Token handles the token request
	Token(c echo.Context) error
	// Signup handles the signup request
	Signup(c echo.Context) error
}

type handlers struct {
	tokenService    token.TokenService
	passwordService password.Password
}

var _ Handlers = &handlers{}

type inject struct {
	tokenService    token.TokenService
	passwordService password.Password
}

// handlerNew creates a new instance of the distribution handlers
func handlerNew(injects ...inject) (Handlers, error) {
	tokenService, err := token.NewTokenService(viper.GetString("auth.jwt.privateKey"))
	if err != nil {
		return nil, err
	}
	passwordService := password.New()
	if len(injects) > 0 {
		ij := injects[0]
		if ij.tokenService != nil {
			tokenService = ij.tokenService
		}
		if ij.passwordService != nil {
			passwordService = ij.passwordService
		}
	}
	return &handlers{
		tokenService:    tokenService,
		passwordService: passwordService,
	}, nil
}

type factory struct{}

var skipAuths = []string{"post:/user/login", "get:/user/token", "get:/user/signup", "get:/user/create"}

func (f factory) Initialize(e *echo.Echo) error {
	userGroup := e.Group("/user")
	userHandler, err := handlerNew()
	if err != nil {
		return err
	}
	userGroup.Use(middlewares.AuthWithConfig(middlewares.AuthConfig{
		Skipper: func(c echo.Context) bool {
			authStr := strings.ToLower(fmt.Sprintf("%s:%s", c.Request().Method, c.Request().URL.Path))
			return slices.Contains(skipAuths, authStr)
		},
	}))
	userGroup.POST("/login", userHandler.Login)
	userGroup.GET("/logout", userHandler.Logout)
	userGroup.GET("/token", userHandler.Token)
	userGroup.GET("/signup", userHandler.Signup)
	userGroup.GET("/create", userHandler.Signup)
	return nil
}

func init() {
	utils.PanicIf(rhandlers.RegisterRouterFactory(path.Base(reflect.TypeOf(handlers{}).PkgPath()), &factory{}))
}
