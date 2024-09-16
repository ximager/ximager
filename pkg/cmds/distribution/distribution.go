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

package distribution

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo-contrib/pprof"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"

	"github.com/go-sigma/sigma/pkg/configs"
	"github.com/go-sigma/sigma/pkg/consts"
	"github.com/go-sigma/sigma/pkg/graceful"
	"github.com/go-sigma/sigma/pkg/handlers"
	"github.com/go-sigma/sigma/pkg/inits"
	"github.com/go-sigma/sigma/pkg/middlewares"
	"github.com/go-sigma/sigma/pkg/storage"
	"github.com/go-sigma/sigma/pkg/types/enums"
	"github.com/go-sigma/sigma/pkg/utils/ptr"
	"github.com/go-sigma/sigma/pkg/utils/serializer"
)

func Serve() error {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{Level: 5}))
	e.Use(echo.MiddlewareFunc(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			n := next(c)
			log.Debug().
				Str("method", c.Request().Method).
				Str("path", c.Request().URL.Path).
				Str("query", c.Request().URL.RawQuery).
				Interface("req-header", c.Request().Header).
				Interface("resp-header", c.Response().Header()).
				Int("status", c.Response().Status).
				Msg("Request debugger")
			return n
		}
	}))

	config := ptr.To(configs.GetConfiguration())

	e.Use(middleware.CORS())
	e.Use(echoprometheus.NewMiddleware(consts.AppName))
	e.GET("/metrics", echoprometheus.NewHandler())
	e.Use(middlewares.Healthz())
	e.JSONSerializer = new(serializer.DefaultJSONSerializer)

	if config.Log.Level == enums.LogLevelDebug || config.Log.Level == enums.LogLevelTrace {
		pprof.Register(e, consts.PprofPath)
	}

	handlers.InitializeDistribution(e)
	err := storage.Initialize(config)
	if err != nil {
		return err
	}

	go func() {
		log.Info().Str("addr", consts.DistributionPort).Msg("Server listening")
		if config.HTTP.TLS.Enabled {
			crtBytes, err := os.ReadFile(config.HTTP.TLS.Certificate)
			if err != nil {
				log.Fatal().Err(err).Str("certificate", config.HTTP.TLS.Certificate).Msgf("Read certificate failed")
				return
			}
			keyBytes, err := os.ReadFile(config.HTTP.TLS.Key)
			if err != nil {
				log.Fatal().Err(err).Str("key", config.HTTP.TLS.Key).Msgf("Read key failed")
				return
			}
			err = e.StartTLS(consts.DistributionPort, crtBytes, keyBytes)
			if err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Listening on interface failed")
			}
		} else {
			err = e.Start(consts.DistributionPort)
			if err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("Listening on interface failed")
			}
		}
	}()

	<-time.After(time.Second * 3)
	err = inits.AfterInitialize(config)
	if err != nil {
		log.Error().Err(err).Msg("init something after server initialized")
	}

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds.
	// Use a buffered channel to avoid missing signals as recommended for signal.Notify
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = e.Shutdown(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Server shutdown failed")
	}

	graceful.Shutdown()

	return nil
}
