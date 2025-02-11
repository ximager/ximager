// Copyright 2024 sigma
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

package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/go-sigma/sigma/pkg/configs"
	"github.com/go-sigma/sigma/pkg/types/enums"
)

func TestRedis(t *testing.T) {
	client, err := New(configs.Configuration{
		Redis: configs.ConfigurationRedis{
			Type: enums.RedisTypeNone,
			URL:  "",
		},
	})
	require.NoError(t, err)
	require.Nil(t, client)

	client, err = New(configs.Configuration{
		Redis: configs.ConfigurationRedis{
			Type: enums.RedisTypeExternal,
			URL:  miniredis.RunT(t).Addr(),
		},
	})
	require.Error(t, err)
	require.Nil(t, client)

	client, err = New(configs.Configuration{
		Redis: configs.ConfigurationRedis{
			Type: enums.RedisTypeExternal,
			URL:  "redis://" + miniredis.RunT(t).Addr(),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, client)
}
