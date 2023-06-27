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

package daemon

import (
	"context"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/ximager/ximager/pkg/consts"
	"github.com/ximager/ximager/pkg/logger"
	"github.com/ximager/ximager/pkg/types/enums"
)

// tasks all daemon tasks
var tasks = map[enums.Daemon]func(context.Context, *asynq.Task) error{}

// topics all daemon topics
var topics = map[enums.Daemon]string{
	enums.DaemonSbom:          consts.TopicSbom,
	enums.DaemonVulnerability: consts.TopicVulnerability,
	enums.DaemonGc:            consts.TopicGc,
}

var (
	// asynqCli asynq client
	asynqCli *asynq.Client
	// asyncSrv asynq server
	asyncSrv *asynq.Server
)

// RegisterTask registers a daemon task
func RegisterTask(name enums.Daemon, handler func(context.Context, *asynq.Task) error) error {
	_, ok := tasks[name]
	if ok {
		return fmt.Errorf("daemon task %q already registered", name)
	}
	tasks[name] = handler
	return nil
}

// InitializeServer initializes the daemon tasks
func InitializeServer() error {
	redisOpt, err := asynq.ParseRedisURI(viper.GetString("redis.url"))
	if err != nil {
		return fmt.Errorf("asynq.ParseRedisURI error: %v", err)
	}
	asyncSrv = asynq.NewServer(
		redisOpt,
		asynq.Config{
			Concurrency: 10,
			Queues: map[string]int{
				"critical": 6,
				"default":  3,
				"low":      1,
			},
			Logger: &logger.Logger{},
		},
	)

	mux := asynq.NewServeMux()
	for taskType, handler := range tasks {
		topic, ok := topics[taskType]
		if !ok {
			return fmt.Errorf("topic for daemon task %q not found", taskType)
		}
		mux.HandleFunc(topic, handler)
	}

	go func() {
		err := asyncSrv.Run(mux)
		if err != nil {
			log.Fatal().Err(err).Msg("srv.Run error")
		}
	}()

	return nil
}

// DeinitServer deinitializes the daemon server
func DeinitServer() {
	asyncSrv.Stop()
	asyncSrv.Shutdown()
}

// InitializeClient initializes the daemon client
func InitializeClient() error {
	redisOpt, err := asynq.ParseRedisURI(viper.GetString("redis.url"))
	if err != nil {
		return fmt.Errorf("asynq.ParseRedisURI error: %v", err)
	}
	asynqCli = asynq.NewClient(redisOpt)
	return nil
}

// DeinitServer deinitializes the daemon server
func DeinitClient() error {
	return asynqCli.Close()
}

// Enqueue enqueues a task
func Enqueue(topic string, payload []byte) error {
	task := asynq.NewTask(topic, payload)
	_, err := asynqCli.Enqueue(task)
	if err != nil {
		return fmt.Errorf("asynqCli.Enqueue error: %v", err)
	}
	return nil
}
