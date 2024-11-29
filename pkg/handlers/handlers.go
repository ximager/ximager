// Copyright 2023 sigma
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

package handlers

import (
	"fmt"

	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.uber.org/dig"

	"github.com/go-sigma/sigma/pkg/handlers/distribution"
	"github.com/go-sigma/sigma/pkg/middlewares"
	"github.com/go-sigma/sigma/pkg/validators"
)

// InitializeDistribution ...
func InitializeDistribution(e *echo.Echo, digCon *dig.Container) {
	e.Any("/v2/*", func() echo.HandlerFunc {
		return func(c echo.Context) error {
			return distribution.All(c, digCon)
		}
	}(), middlewares.AuthWithConfig(middlewares.AuthConfig{DS: true}))
}

// Initialize ...
func Initialize(e *echo.Echo, c *dig.Container) error {
	e.Any("/swagger/*", echoSwagger.WrapHandler)

	validators.Initialize(e)

	// c := dig.New()

	// c.Provide(func() configs.Configuration {
	// 	return ptr.To(configs.GetConfiguration())
	// })
	// c.Provide(func() dao.UserServiceFactory {
	// 	return dao.NewUserServiceFactory()
	// })
	// c.Provide(func() password.Password {
	// 	return password.New()
	// })
	// c.Provide(func(config configs.Configuration) (token.TokenService, error) {
	// 	return token.NewTokenService(config.Auth.Jwt.PrivateKey)
	// })

	for name, factory := range routerFactories {
		if err := factory.Initialize(c); err != nil {
			return fmt.Errorf("failed to initialize router factory %q: %v", name, err)
		}
	}

	return nil
}

// Factory is the interface for the storage router factory
type Factory interface {
	Initialize(c *dig.Container) error
}

var routerFactories = make(map[string]Factory)

// RegisterRouterFactory registers a new router factory
func RegisterRouterFactory(name string, factory Factory) error {
	if _, ok := routerFactories[name]; ok {
		return fmt.Errorf("driver %q already registered", name)
	}
	routerFactories[name] = factory
	return nil
}
