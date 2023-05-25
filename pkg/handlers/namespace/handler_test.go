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

package namespace

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"

	daomock "github.com/ximager/ximager/pkg/dal/dao/mocks"
)

func TestFactory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	daoMockNamespaceService := daomock.NewMockNamespaceServiceFactory(ctrl)
	daoMockArtifactService := daomock.NewMockArtifactServiceFactory(ctrl)

	handler := handlerNew(inject{namespaceServiceFactory: daoMockNamespaceService, artifactServiceFactory: daoMockArtifactService})
	assert.NotNil(t, handler)

	f := factory{}
	err := f.Initialize(echo.New())
	assert.NoError(t, err)
}
