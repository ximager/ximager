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

package namespaces

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
	"go.uber.org/mock/gomock"

	"github.com/ximager/ximager/pkg/consts"
	"github.com/ximager/ximager/pkg/dal"
	"github.com/ximager/ximager/pkg/dal/dao"
	daomock "github.com/ximager/ximager/pkg/dal/dao/mocks"
	"github.com/ximager/ximager/pkg/dal/models"
	"github.com/ximager/ximager/pkg/dal/query"
	"github.com/ximager/ximager/pkg/logger"
	"github.com/ximager/ximager/pkg/tests"
	"github.com/ximager/ximager/pkg/types/enums"
	"github.com/ximager/ximager/pkg/utils/ptr"
	"github.com/ximager/ximager/pkg/validators"
)

func TestPutNamespace(t *testing.T) {
	logger.SetLevel("debug")
	e := echo.New()
	validators.Initialize(e)
	err := tests.Initialize(t)
	assert.NoError(t, err)
	err = tests.DB.Init()
	assert.NoError(t, err)
	defer func() {
		conn, err := dal.DB.DB()
		assert.NoError(t, err)
		err = conn.Close()
		assert.NoError(t, err)
		err = tests.DB.DeInit()
		assert.NoError(t, err)
	}()

	namespaceHandler := handlerNew()

	userServiceFactory := dao.NewUserServiceFactory()
	userService := userServiceFactory.New()

	ctx := context.Background()
	userObj := &models.User{Provider: enums.ProviderLocal, Username: "put-namespace", Password: ptr.Of("test"), Email: ptr.Of("test@gmail.com")}
	err = userService.Create(ctx, userObj)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"test","size_limit":10}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(consts.ContextUser, userObj)
	err = namespaceHandler.PostNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, c.Response().Status)
	resultID := gjson.GetBytes(rec.Body.Bytes(), "id").Int()

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"description":"test"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatInt(resultID, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	fmt.Println(rec.Body.String())
	assert.Equal(t, http.StatusNoContent, c.Response().Status)

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"size_limit":101}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatInt(resultID, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	fmt.Println(rec.Body.String())
	assert.Equal(t, http.StatusNoContent, c.Response().Status)

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"visibility":"test"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatInt(resultID, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, c.Response().Status)

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"size_limit":1}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatInt(resultID, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, c.Response().Status)

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"description":"test"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatUint(3, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, c.Response().Status)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	daoMockNamespaceService := daomock.NewMockNamespaceService(ctrl)
	daoMockNamespaceService.EXPECT().UpdateByID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _ int64, _ map[string]any) error {
		return fmt.Errorf("test")
	}).Times(1)
	daoMockNamespaceService.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _ int64) (*models.Namespace, error) {
		return &models.Namespace{Name: "test", SizeLimit: 100}, nil
	}).Times(1)

	daoMockNamespaceServiceFactory := daomock.NewMockNamespaceServiceFactory(ctrl)
	daoMockNamespaceServiceFactory.EXPECT().New(gomock.Any()).DoAndReturn(func(txs ...*query.Query) dao.NamespaceService {
		return daoMockNamespaceService
	}).Times(1)

	namespaceHandler = handlerNew(inject{namespaceServiceFactory: daoMockNamespaceServiceFactory})

	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"description":"test"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatUint(3, 10))
	err = namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, c.Response().Status)
}

func TestPutNamespaceFailed1(t *testing.T) {
	logger.SetLevel("debug")
	e := echo.New()
	validators.Initialize(e)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	daoMockNamespaceService := daomock.NewMockNamespaceService(ctrl)
	daoMockNamespaceService.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _ int64) (*models.Namespace, error) {
		return nil, fmt.Errorf("test")
	}).Times(1)

	daoMockNamespaceServiceFactory := daomock.NewMockNamespaceServiceFactory(ctrl)
	daoMockNamespaceServiceFactory.EXPECT().New(gomock.Any()).DoAndReturn(func(txs ...*query.Query) dao.NamespaceService {
		return daoMockNamespaceService
	}).Times(1)

	namespaceHandler := handlerNew(inject{namespaceServiceFactory: daoMockNamespaceServiceFactory})

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"limit":10}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(strconv.FormatUint(3, 10))
	err := namespaceHandler.PutNamespace(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, c.Response().Status)
}
