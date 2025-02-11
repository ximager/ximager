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

package configs

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"github.com/go-sigma/sigma/pkg/types/enums"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

func init() {
	checkers = append(checkers, checkRedis, checkDatabase, checkStorage)
}

func checkRedis(config Configuration) error {
	if config.Redis.Type == enums.RedisTypeNone {
		return nil
	}
	if config.Redis.Type != enums.RedisTypeExternal {
		return fmt.Errorf("Unknown redis type: %s", config.Redis.Type)
	}
	redisOpt, err := redis.ParseURL(config.Redis.URL)
	if err != nil {
		return fmt.Errorf("redis.ParseURL error: %v", err)
	}
	redisCli := redis.NewClient(redisOpt)
	err = redisCli.Ping(context.Background()).Err()
	if err != nil {
		return fmt.Errorf("redis.Ping error: %v", err)
	}
	err = redisCli.Close()
	if err != nil {
		return fmt.Errorf("redis.Close error: %v", err)
	}
	log.Info().Msg("redis check passed")
	return nil
}

func checkDatabase(config Configuration) error {
	dbType := config.Database.Type

	switch dbType {
	case enums.DatabaseMysql:
		return checkMysql(config)
	case enums.DatabasePostgresql:
		return checkPostgresql(config)
	case enums.DatabaseSqlite3:
		return nil
	default:
		return fmt.Errorf("unknown database type: %s", dbType)
	}
}

func checkMysql(config Configuration) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.Database.Mysql.Username, config.Database.Mysql.Password,
		config.Database.Mysql.Host, config.Database.Mysql.Port,
		config.Database.Mysql.Database) // TODO: query values
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("sql.Open error: %v", err)
	}
	err = db.Ping()
	if err != nil {
		return fmt.Errorf("db.Ping error: %v", err)
	}
	err = db.Close()
	if err != nil {
		return fmt.Errorf("db.Close error: %v", err)
	}
	log.Info().Msg("mysql check passed")
	return nil
}

func checkPostgresql(config Configuration) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		config.Database.Postgresql.Username, config.Database.Postgresql.Password,
		config.Database.Postgresql.Host, config.Database.Postgresql.Port,
		config.Database.Postgresql.Database))
	if err != nil {
		return fmt.Errorf("pgx.Connect error: %v", err)
	}
	err = conn.Close(ctx)
	if err != nil {
		return fmt.Errorf("conn.Close error: %v", err)
	}
	log.Info().Msg("postgresql check passed")
	return nil
}

func checkStorage(config Configuration) error {
	storageType := config.Storage.Type
	switch storageType {
	case enums.StorageTypeFilesystem:
		return nil
	case enums.StorageTypeS3:
		return checkStorageS3(config)
	default:
		return fmt.Errorf("Not support storage type")
	}
}

func checkStorageS3(cfg Configuration) error {
	c, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Storage.S3.Region),
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     cfg.Storage.S3.Ak,
				SecretAccessKey: cfg.Storage.S3.Sk,
			}, nil
		})),
	)
	if err != nil {
		return err
	}
	s3Cli := s3.NewFromConfig(c, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Storage.S3.Endpoint)
		o.UsePathStyle = cfg.Storage.S3.ForcePathStyle
	})
	_, err = s3Cli.HeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: aws.String(cfg.Storage.S3.Bucket)})
	if err != nil {
		return fmt.Errorf("s3.HeadBucket error: %v", err)
	}
	log.Info().Msg("s3 obs check passed")
	return nil
}
