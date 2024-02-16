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

package webhooks

import "github.com/labstack/echo/v4"

// GetWebhookPing handles the send webhook ping event request
//
//	@Summary	Send a webhook ping event
//	@security	BasicAuth
//	@Tags		Webhook
//	@Accept		json
//	@Produce	json
//	@Router		/webhooks/{webhook_id}/ping [get]
//	@Param		webhook_id	path	int64	true	"Webhook id"
//	@Success	204
//	@Failure	500	{object}	xerrors.ErrCode
//	@Failure	401	{object}	xerrors.ErrCode
func (h *handler) GetWebhookPing(c echo.Context) error {
	return nil
}
