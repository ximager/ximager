// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.

package query

import (
	"context"
	"database/sql"

	"gorm.io/gorm"

	"gorm.io/gen"

	"gorm.io/plugin/dbresolver"
)

var (
	Q                             = new(Query)
	Artifact                      *artifact
	ArtifactSbom                  *artifactSbom
	ArtifactVulnerability         *artifactVulnerability
	Audit                         *audit
	Blob                          *blob
	BlobUpload                    *blobUpload
	Builder                       *builder
	BuilderRunner                 *builderRunner
	Cache                         *cache
	CasbinRule                    *casbinRule
	CodeRepository                *codeRepository
	CodeRepositoryBranch          *codeRepositoryBranch
	CodeRepositoryCloneCredential *codeRepositoryCloneCredential
	CodeRepositoryOwner           *codeRepositoryOwner
	DaemonGcArtifactRecord        *daemonGcArtifactRecord
	DaemonGcArtifactRunner        *daemonGcArtifactRunner
	DaemonGcBlobRecord            *daemonGcBlobRecord
	DaemonGcBlobRunner            *daemonGcBlobRunner
	DaemonGcRepositoryRecord      *daemonGcRepositoryRecord
	DaemonGcRepositoryRunner      *daemonGcRepositoryRunner
	DaemonLog                     *daemonLog
	Locker                        *locker
	Namespace                     *namespace
	Repository                    *repository
	Setting                       *setting
	Tag                           *tag
	User                          *user
	User3rdParty                  *user3rdParty
	UserRecoverCode               *userRecoverCode
	Webhook                       *webhook
	WebhookLog                    *webhookLog
	WorkQueue                     *workQueue
)

func SetDefault(db *gorm.DB, opts ...gen.DOOption) {
	*Q = *Use(db, opts...)
	Artifact = &Q.Artifact
	ArtifactSbom = &Q.ArtifactSbom
	ArtifactVulnerability = &Q.ArtifactVulnerability
	Audit = &Q.Audit
	Blob = &Q.Blob
	BlobUpload = &Q.BlobUpload
	Builder = &Q.Builder
	BuilderRunner = &Q.BuilderRunner
	Cache = &Q.Cache
	CasbinRule = &Q.CasbinRule
	CodeRepository = &Q.CodeRepository
	CodeRepositoryBranch = &Q.CodeRepositoryBranch
	CodeRepositoryCloneCredential = &Q.CodeRepositoryCloneCredential
	CodeRepositoryOwner = &Q.CodeRepositoryOwner
	DaemonGcArtifactRecord = &Q.DaemonGcArtifactRecord
	DaemonGcArtifactRunner = &Q.DaemonGcArtifactRunner
	DaemonGcBlobRecord = &Q.DaemonGcBlobRecord
	DaemonGcBlobRunner = &Q.DaemonGcBlobRunner
	DaemonGcRepositoryRecord = &Q.DaemonGcRepositoryRecord
	DaemonGcRepositoryRunner = &Q.DaemonGcRepositoryRunner
	DaemonLog = &Q.DaemonLog
	Locker = &Q.Locker
	Namespace = &Q.Namespace
	Repository = &Q.Repository
	Setting = &Q.Setting
	Tag = &Q.Tag
	User = &Q.User
	User3rdParty = &Q.User3rdParty
	UserRecoverCode = &Q.UserRecoverCode
	Webhook = &Q.Webhook
	WebhookLog = &Q.WebhookLog
	WorkQueue = &Q.WorkQueue
}

func Use(db *gorm.DB, opts ...gen.DOOption) *Query {
	return &Query{
		db:                            db,
		Artifact:                      newArtifact(db, opts...),
		ArtifactSbom:                  newArtifactSbom(db, opts...),
		ArtifactVulnerability:         newArtifactVulnerability(db, opts...),
		Audit:                         newAudit(db, opts...),
		Blob:                          newBlob(db, opts...),
		BlobUpload:                    newBlobUpload(db, opts...),
		Builder:                       newBuilder(db, opts...),
		BuilderRunner:                 newBuilderRunner(db, opts...),
		Cache:                         newCache(db, opts...),
		CasbinRule:                    newCasbinRule(db, opts...),
		CodeRepository:                newCodeRepository(db, opts...),
		CodeRepositoryBranch:          newCodeRepositoryBranch(db, opts...),
		CodeRepositoryCloneCredential: newCodeRepositoryCloneCredential(db, opts...),
		CodeRepositoryOwner:           newCodeRepositoryOwner(db, opts...),
		DaemonGcArtifactRecord:        newDaemonGcArtifactRecord(db, opts...),
		DaemonGcArtifactRunner:        newDaemonGcArtifactRunner(db, opts...),
		DaemonGcBlobRecord:            newDaemonGcBlobRecord(db, opts...),
		DaemonGcBlobRunner:            newDaemonGcBlobRunner(db, opts...),
		DaemonGcRepositoryRecord:      newDaemonGcRepositoryRecord(db, opts...),
		DaemonGcRepositoryRunner:      newDaemonGcRepositoryRunner(db, opts...),
		DaemonLog:                     newDaemonLog(db, opts...),
		Locker:                        newLocker(db, opts...),
		Namespace:                     newNamespace(db, opts...),
		Repository:                    newRepository(db, opts...),
		Setting:                       newSetting(db, opts...),
		Tag:                           newTag(db, opts...),
		User:                          newUser(db, opts...),
		User3rdParty:                  newUser3rdParty(db, opts...),
		UserRecoverCode:               newUserRecoverCode(db, opts...),
		Webhook:                       newWebhook(db, opts...),
		WebhookLog:                    newWebhookLog(db, opts...),
		WorkQueue:                     newWorkQueue(db, opts...),
	}
}

type Query struct {
	db *gorm.DB

	Artifact                      artifact
	ArtifactSbom                  artifactSbom
	ArtifactVulnerability         artifactVulnerability
	Audit                         audit
	Blob                          blob
	BlobUpload                    blobUpload
	Builder                       builder
	BuilderRunner                 builderRunner
	Cache                         cache
	CasbinRule                    casbinRule
	CodeRepository                codeRepository
	CodeRepositoryBranch          codeRepositoryBranch
	CodeRepositoryCloneCredential codeRepositoryCloneCredential
	CodeRepositoryOwner           codeRepositoryOwner
	DaemonGcArtifactRecord        daemonGcArtifactRecord
	DaemonGcArtifactRunner        daemonGcArtifactRunner
	DaemonGcBlobRecord            daemonGcBlobRecord
	DaemonGcBlobRunner            daemonGcBlobRunner
	DaemonGcRepositoryRecord      daemonGcRepositoryRecord
	DaemonGcRepositoryRunner      daemonGcRepositoryRunner
	DaemonLog                     daemonLog
	Locker                        locker
	Namespace                     namespace
	Repository                    repository
	Setting                       setting
	Tag                           tag
	User                          user
	User3rdParty                  user3rdParty
	UserRecoverCode               userRecoverCode
	Webhook                       webhook
	WebhookLog                    webhookLog
	WorkQueue                     workQueue
}

func (q *Query) Available() bool { return q.db != nil }

func (q *Query) clone(db *gorm.DB) *Query {
	return &Query{
		db:                            db,
		Artifact:                      q.Artifact.clone(db),
		ArtifactSbom:                  q.ArtifactSbom.clone(db),
		ArtifactVulnerability:         q.ArtifactVulnerability.clone(db),
		Audit:                         q.Audit.clone(db),
		Blob:                          q.Blob.clone(db),
		BlobUpload:                    q.BlobUpload.clone(db),
		Builder:                       q.Builder.clone(db),
		BuilderRunner:                 q.BuilderRunner.clone(db),
		Cache:                         q.Cache.clone(db),
		CasbinRule:                    q.CasbinRule.clone(db),
		CodeRepository:                q.CodeRepository.clone(db),
		CodeRepositoryBranch:          q.CodeRepositoryBranch.clone(db),
		CodeRepositoryCloneCredential: q.CodeRepositoryCloneCredential.clone(db),
		CodeRepositoryOwner:           q.CodeRepositoryOwner.clone(db),
		DaemonGcArtifactRecord:        q.DaemonGcArtifactRecord.clone(db),
		DaemonGcArtifactRunner:        q.DaemonGcArtifactRunner.clone(db),
		DaemonGcBlobRecord:            q.DaemonGcBlobRecord.clone(db),
		DaemonGcBlobRunner:            q.DaemonGcBlobRunner.clone(db),
		DaemonGcRepositoryRecord:      q.DaemonGcRepositoryRecord.clone(db),
		DaemonGcRepositoryRunner:      q.DaemonGcRepositoryRunner.clone(db),
		DaemonLog:                     q.DaemonLog.clone(db),
		Locker:                        q.Locker.clone(db),
		Namespace:                     q.Namespace.clone(db),
		Repository:                    q.Repository.clone(db),
		Setting:                       q.Setting.clone(db),
		Tag:                           q.Tag.clone(db),
		User:                          q.User.clone(db),
		User3rdParty:                  q.User3rdParty.clone(db),
		UserRecoverCode:               q.UserRecoverCode.clone(db),
		Webhook:                       q.Webhook.clone(db),
		WebhookLog:                    q.WebhookLog.clone(db),
		WorkQueue:                     q.WorkQueue.clone(db),
	}
}

func (q *Query) ReadDB() *Query {
	return q.ReplaceDB(q.db.Clauses(dbresolver.Read))
}

func (q *Query) WriteDB() *Query {
	return q.ReplaceDB(q.db.Clauses(dbresolver.Write))
}

func (q *Query) ReplaceDB(db *gorm.DB) *Query {
	return &Query{
		db:                            db,
		Artifact:                      q.Artifact.replaceDB(db),
		ArtifactSbom:                  q.ArtifactSbom.replaceDB(db),
		ArtifactVulnerability:         q.ArtifactVulnerability.replaceDB(db),
		Audit:                         q.Audit.replaceDB(db),
		Blob:                          q.Blob.replaceDB(db),
		BlobUpload:                    q.BlobUpload.replaceDB(db),
		Builder:                       q.Builder.replaceDB(db),
		BuilderRunner:                 q.BuilderRunner.replaceDB(db),
		Cache:                         q.Cache.replaceDB(db),
		CasbinRule:                    q.CasbinRule.replaceDB(db),
		CodeRepository:                q.CodeRepository.replaceDB(db),
		CodeRepositoryBranch:          q.CodeRepositoryBranch.replaceDB(db),
		CodeRepositoryCloneCredential: q.CodeRepositoryCloneCredential.replaceDB(db),
		CodeRepositoryOwner:           q.CodeRepositoryOwner.replaceDB(db),
		DaemonGcArtifactRecord:        q.DaemonGcArtifactRecord.replaceDB(db),
		DaemonGcArtifactRunner:        q.DaemonGcArtifactRunner.replaceDB(db),
		DaemonGcBlobRecord:            q.DaemonGcBlobRecord.replaceDB(db),
		DaemonGcBlobRunner:            q.DaemonGcBlobRunner.replaceDB(db),
		DaemonGcRepositoryRecord:      q.DaemonGcRepositoryRecord.replaceDB(db),
		DaemonGcRepositoryRunner:      q.DaemonGcRepositoryRunner.replaceDB(db),
		DaemonLog:                     q.DaemonLog.replaceDB(db),
		Locker:                        q.Locker.replaceDB(db),
		Namespace:                     q.Namespace.replaceDB(db),
		Repository:                    q.Repository.replaceDB(db),
		Setting:                       q.Setting.replaceDB(db),
		Tag:                           q.Tag.replaceDB(db),
		User:                          q.User.replaceDB(db),
		User3rdParty:                  q.User3rdParty.replaceDB(db),
		UserRecoverCode:               q.UserRecoverCode.replaceDB(db),
		Webhook:                       q.Webhook.replaceDB(db),
		WebhookLog:                    q.WebhookLog.replaceDB(db),
		WorkQueue:                     q.WorkQueue.replaceDB(db),
	}
}

type queryCtx struct {
	Artifact                      *artifactDo
	ArtifactSbom                  *artifactSbomDo
	ArtifactVulnerability         *artifactVulnerabilityDo
	Audit                         *auditDo
	Blob                          *blobDo
	BlobUpload                    *blobUploadDo
	Builder                       *builderDo
	BuilderRunner                 *builderRunnerDo
	Cache                         *cacheDo
	CasbinRule                    *casbinRuleDo
	CodeRepository                *codeRepositoryDo
	CodeRepositoryBranch          *codeRepositoryBranchDo
	CodeRepositoryCloneCredential *codeRepositoryCloneCredentialDo
	CodeRepositoryOwner           *codeRepositoryOwnerDo
	DaemonGcArtifactRecord        *daemonGcArtifactRecordDo
	DaemonGcArtifactRunner        *daemonGcArtifactRunnerDo
	DaemonGcBlobRecord            *daemonGcBlobRecordDo
	DaemonGcBlobRunner            *daemonGcBlobRunnerDo
	DaemonGcRepositoryRecord      *daemonGcRepositoryRecordDo
	DaemonGcRepositoryRunner      *daemonGcRepositoryRunnerDo
	DaemonLog                     *daemonLogDo
	Locker                        *lockerDo
	Namespace                     *namespaceDo
	Repository                    *repositoryDo
	Setting                       *settingDo
	Tag                           *tagDo
	User                          *userDo
	User3rdParty                  *user3rdPartyDo
	UserRecoverCode               *userRecoverCodeDo
	Webhook                       *webhookDo
	WebhookLog                    *webhookLogDo
	WorkQueue                     *workQueueDo
}

func (q *Query) WithContext(ctx context.Context) *queryCtx {
	return &queryCtx{
		Artifact:                      q.Artifact.WithContext(ctx),
		ArtifactSbom:                  q.ArtifactSbom.WithContext(ctx),
		ArtifactVulnerability:         q.ArtifactVulnerability.WithContext(ctx),
		Audit:                         q.Audit.WithContext(ctx),
		Blob:                          q.Blob.WithContext(ctx),
		BlobUpload:                    q.BlobUpload.WithContext(ctx),
		Builder:                       q.Builder.WithContext(ctx),
		BuilderRunner:                 q.BuilderRunner.WithContext(ctx),
		Cache:                         q.Cache.WithContext(ctx),
		CasbinRule:                    q.CasbinRule.WithContext(ctx),
		CodeRepository:                q.CodeRepository.WithContext(ctx),
		CodeRepositoryBranch:          q.CodeRepositoryBranch.WithContext(ctx),
		CodeRepositoryCloneCredential: q.CodeRepositoryCloneCredential.WithContext(ctx),
		CodeRepositoryOwner:           q.CodeRepositoryOwner.WithContext(ctx),
		DaemonGcArtifactRecord:        q.DaemonGcArtifactRecord.WithContext(ctx),
		DaemonGcArtifactRunner:        q.DaemonGcArtifactRunner.WithContext(ctx),
		DaemonGcBlobRecord:            q.DaemonGcBlobRecord.WithContext(ctx),
		DaemonGcBlobRunner:            q.DaemonGcBlobRunner.WithContext(ctx),
		DaemonGcRepositoryRecord:      q.DaemonGcRepositoryRecord.WithContext(ctx),
		DaemonGcRepositoryRunner:      q.DaemonGcRepositoryRunner.WithContext(ctx),
		DaemonLog:                     q.DaemonLog.WithContext(ctx),
		Locker:                        q.Locker.WithContext(ctx),
		Namespace:                     q.Namespace.WithContext(ctx),
		Repository:                    q.Repository.WithContext(ctx),
		Setting:                       q.Setting.WithContext(ctx),
		Tag:                           q.Tag.WithContext(ctx),
		User:                          q.User.WithContext(ctx),
		User3rdParty:                  q.User3rdParty.WithContext(ctx),
		UserRecoverCode:               q.UserRecoverCode.WithContext(ctx),
		Webhook:                       q.Webhook.WithContext(ctx),
		WebhookLog:                    q.WebhookLog.WithContext(ctx),
		WorkQueue:                     q.WorkQueue.WithContext(ctx),
	}
}

func (q *Query) Transaction(fc func(tx *Query) error, opts ...*sql.TxOptions) error {
	return q.db.Transaction(func(tx *gorm.DB) error { return fc(q.clone(tx)) }, opts...)
}

func (q *Query) Begin(opts ...*sql.TxOptions) *QueryTx {
	tx := q.db.Begin(opts...)
	return &QueryTx{Query: q.clone(tx), Error: tx.Error}
}

type QueryTx struct {
	*Query
	Error error
}

func (q *QueryTx) Commit() error {
	return q.db.Commit().Error
}

func (q *QueryTx) Rollback() error {
	return q.db.Rollback().Error
}

func (q *QueryTx) SavePoint(name string) error {
	return q.db.SavePoint(name).Error
}

func (q *QueryTx) RollbackTo(name string) error {
	return q.db.RollbackTo(name).Error
}
