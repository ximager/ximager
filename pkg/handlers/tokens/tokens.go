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

package token

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/go-sigma/sigma/pkg/types"
	"github.com/go-sigma/sigma/pkg/utils/ptr"
	"github.com/go-sigma/sigma/pkg/xerrors"
)

// Token generate token for docker client
//
//	@Summary	Generate token
//	@Tags		Token
//	@security	BasicAuth
//	@Accept		json
//	@Produce	json
//	@Router		/tokens [get]
//	@Success	200	{object}	types.PostUserTokenResponse
//	@Failure	401	{object}	xerrors.ErrCode
//	@Failure	500	{object}	xerrors.ErrCode
func (h *handlers) Token(c echo.Context) error {
	ctx := log.Logger.WithContext(c.Request().Context())

	username, pwd, ok := c.Request().BasicAuth()
	if !ok {
		log.Error().Str("Authorization", c.Request().Header.Get("Authorization")).Msg("Basic auth failed")
		return xerrors.NewDSError(c, xerrors.DSErrCodeUnauthorized)
	}

	userService := h.userServiceFactory.New()
	user, err := userService.GetByUsername(ctx, username)
	if err != nil {
		log.Error().Err(err).Msg("Get user by username failed")
		return xerrors.NewDSError(c, xerrors.DSErrCodeUnauthorized)
	}

	verify := h.passwordService.Verify(pwd, ptr.To(user.Password))
	if !verify {
		log.Error().Err(err).Msg("Verify password failed")
		return xerrors.NewDSError(c, xerrors.DSErrCodeUnauthorized)
	}

	token, err := h.tokenService.New(user.ID, viper.GetDuration("auth.jwt.ttl"))
	if err != nil {
		log.Error().Err(err).Msg("Create token failed")
		return xerrors.NewHTTPError(c, xerrors.HTTPErrCodeInternalError, err.Error())
	}

	return c.JSON(http.StatusOK, types.PostUserTokenResponse{
		Token:     token,
		ExpiresIn: int(viper.GetDuration("auth.jwt.ttl").Seconds()),
		IssuedAt:  time.Now().Format(time.RFC3339),
	})
}
