// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.

package query

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"

	"gorm.io/gen"
	"gorm.io/gen/field"

	"gorm.io/plugin/dbresolver"

	"github.com/go-sigma/sigma/pkg/dal/models"
)

func newTag(db *gorm.DB, opts ...gen.DOOption) tag {
	_tag := tag{}

	_tag.tagDo.UseDB(db, opts...)
	_tag.tagDo.UseModel(&models.Tag{})

	tableName := _tag.tagDo.TableName()
	_tag.ALL = field.NewAsterisk(tableName)
	_tag.CreatedAt = field.NewInt64(tableName, "created_at")
	_tag.UpdatedAt = field.NewInt64(tableName, "updated_at")
	_tag.DeletedAt = field.NewUint64(tableName, "deleted_at")
	_tag.ID = field.NewInt64(tableName, "id")
	_tag.RepositoryID = field.NewInt64(tableName, "repository_id")
	_tag.ArtifactID = field.NewInt64(tableName, "artifact_id")
	_tag.Name = field.NewString(tableName, "name")
	_tag.LastPull = field.NewField(tableName, "last_pull")
	_tag.PushedAt = field.NewTime(tableName, "pushed_at")
	_tag.PullTimes = field.NewInt64(tableName, "pull_times")
	_tag.Repository = tagBelongsToRepository{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Repository", "models.Repository"),
		Namespace: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Repository.Namespace", "models.Namespace"),
		},
		Builder: struct {
			field.RelationField
			Repository struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Repository.Builder", "models.Builder"),
			Repository: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Repository.Builder.Repository", "models.Repository"),
			},
		},
	}

	_tag.Artifact = tagBelongsToArtifact{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Artifact", "models.Artifact"),
		Repository: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Artifact.Repository", "models.Repository"),
		},
		Referrer: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Artifact.Referrer", "models.Artifact"),
		},
		Vulnerability: struct {
			field.RelationField
			Artifact struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Artifact.Vulnerability", "models.ArtifactVulnerability"),
			Artifact: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Vulnerability.Artifact", "models.Artifact"),
			},
		},
		Sbom: struct {
			field.RelationField
			Artifact struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Artifact.Sbom", "models.ArtifactSbom"),
			Artifact: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Sbom.Artifact", "models.Artifact"),
			},
		},
		Tags: struct {
			field.RelationField
			Repository struct {
				field.RelationField
			}
			Artifact struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Artifact.Tags", "models.Tag"),
			Repository: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Tags.Repository", "models.Repository"),
			},
			Artifact: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Tags.Artifact", "models.Artifact"),
			},
		},
		ArtifactIndexes: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Artifact.ArtifactIndexes", "models.Artifact"),
		},
		Blobs: struct {
			field.RelationField
			Artifacts struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Artifact.Blobs", "models.Blob"),
			Artifacts: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Blobs.Artifacts", "models.Artifact"),
			},
		},
	}

	_tag.fillFieldMap()

	return _tag
}

type tag struct {
	tagDo tagDo

	ALL          field.Asterisk
	CreatedAt    field.Int64
	UpdatedAt    field.Int64
	DeletedAt    field.Uint64
	ID           field.Int64
	RepositoryID field.Int64
	ArtifactID   field.Int64
	Name         field.String
	LastPull     field.Field
	PushedAt     field.Time
	PullTimes    field.Int64
	Repository   tagBelongsToRepository

	Artifact tagBelongsToArtifact

	fieldMap map[string]field.Expr
}

func (t tag) Table(newTableName string) *tag {
	t.tagDo.UseTable(newTableName)
	return t.updateTableName(newTableName)
}

func (t tag) As(alias string) *tag {
	t.tagDo.DO = *(t.tagDo.As(alias).(*gen.DO))
	return t.updateTableName(alias)
}

func (t *tag) updateTableName(table string) *tag {
	t.ALL = field.NewAsterisk(table)
	t.CreatedAt = field.NewInt64(table, "created_at")
	t.UpdatedAt = field.NewInt64(table, "updated_at")
	t.DeletedAt = field.NewUint64(table, "deleted_at")
	t.ID = field.NewInt64(table, "id")
	t.RepositoryID = field.NewInt64(table, "repository_id")
	t.ArtifactID = field.NewInt64(table, "artifact_id")
	t.Name = field.NewString(table, "name")
	t.LastPull = field.NewField(table, "last_pull")
	t.PushedAt = field.NewTime(table, "pushed_at")
	t.PullTimes = field.NewInt64(table, "pull_times")

	t.fillFieldMap()

	return t
}

func (t *tag) WithContext(ctx context.Context) *tagDo { return t.tagDo.WithContext(ctx) }

func (t tag) TableName() string { return t.tagDo.TableName() }

func (t tag) Alias() string { return t.tagDo.Alias() }

func (t tag) Columns(cols ...field.Expr) gen.Columns { return t.tagDo.Columns(cols...) }

func (t *tag) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := t.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (t *tag) fillFieldMap() {
	t.fieldMap = make(map[string]field.Expr, 12)
	t.fieldMap["created_at"] = t.CreatedAt
	t.fieldMap["updated_at"] = t.UpdatedAt
	t.fieldMap["deleted_at"] = t.DeletedAt
	t.fieldMap["id"] = t.ID
	t.fieldMap["repository_id"] = t.RepositoryID
	t.fieldMap["artifact_id"] = t.ArtifactID
	t.fieldMap["name"] = t.Name
	t.fieldMap["last_pull"] = t.LastPull
	t.fieldMap["pushed_at"] = t.PushedAt
	t.fieldMap["pull_times"] = t.PullTimes

}

func (t tag) clone(db *gorm.DB) tag {
	t.tagDo.ReplaceConnPool(db.Statement.ConnPool)
	return t
}

func (t tag) replaceDB(db *gorm.DB) tag {
	t.tagDo.ReplaceDB(db)
	return t
}

type tagBelongsToRepository struct {
	db *gorm.DB

	field.RelationField

	Namespace struct {
		field.RelationField
	}
	Builder struct {
		field.RelationField
		Repository struct {
			field.RelationField
		}
	}
}

func (a tagBelongsToRepository) Where(conds ...field.Expr) *tagBelongsToRepository {
	if len(conds) == 0 {
		return &a
	}

	exprs := make([]clause.Expression, 0, len(conds))
	for _, cond := range conds {
		exprs = append(exprs, cond.BeCond().(clause.Expression))
	}
	a.db = a.db.Clauses(clause.Where{Exprs: exprs})
	return &a
}

func (a tagBelongsToRepository) WithContext(ctx context.Context) *tagBelongsToRepository {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a tagBelongsToRepository) Session(session *gorm.Session) *tagBelongsToRepository {
	a.db = a.db.Session(session)
	return &a
}

func (a tagBelongsToRepository) Model(m *models.Tag) *tagBelongsToRepositoryTx {
	return &tagBelongsToRepositoryTx{a.db.Model(m).Association(a.Name())}
}

type tagBelongsToRepositoryTx struct{ tx *gorm.Association }

func (a tagBelongsToRepositoryTx) Find() (result *models.Repository, err error) {
	return result, a.tx.Find(&result)
}

func (a tagBelongsToRepositoryTx) Append(values ...*models.Repository) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a tagBelongsToRepositoryTx) Replace(values ...*models.Repository) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a tagBelongsToRepositoryTx) Delete(values ...*models.Repository) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a tagBelongsToRepositoryTx) Clear() error {
	return a.tx.Clear()
}

func (a tagBelongsToRepositoryTx) Count() int64 {
	return a.tx.Count()
}

type tagBelongsToArtifact struct {
	db *gorm.DB

	field.RelationField

	Repository struct {
		field.RelationField
	}
	Referrer struct {
		field.RelationField
	}
	Vulnerability struct {
		field.RelationField
		Artifact struct {
			field.RelationField
		}
	}
	Sbom struct {
		field.RelationField
		Artifact struct {
			field.RelationField
		}
	}
	Tags struct {
		field.RelationField
		Repository struct {
			field.RelationField
		}
		Artifact struct {
			field.RelationField
		}
	}
	ArtifactIndexes struct {
		field.RelationField
	}
	Blobs struct {
		field.RelationField
		Artifacts struct {
			field.RelationField
		}
	}
}

func (a tagBelongsToArtifact) Where(conds ...field.Expr) *tagBelongsToArtifact {
	if len(conds) == 0 {
		return &a
	}

	exprs := make([]clause.Expression, 0, len(conds))
	for _, cond := range conds {
		exprs = append(exprs, cond.BeCond().(clause.Expression))
	}
	a.db = a.db.Clauses(clause.Where{Exprs: exprs})
	return &a
}

func (a tagBelongsToArtifact) WithContext(ctx context.Context) *tagBelongsToArtifact {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a tagBelongsToArtifact) Session(session *gorm.Session) *tagBelongsToArtifact {
	a.db = a.db.Session(session)
	return &a
}

func (a tagBelongsToArtifact) Model(m *models.Tag) *tagBelongsToArtifactTx {
	return &tagBelongsToArtifactTx{a.db.Model(m).Association(a.Name())}
}

type tagBelongsToArtifactTx struct{ tx *gorm.Association }

func (a tagBelongsToArtifactTx) Find() (result *models.Artifact, err error) {
	return result, a.tx.Find(&result)
}

func (a tagBelongsToArtifactTx) Append(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a tagBelongsToArtifactTx) Replace(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a tagBelongsToArtifactTx) Delete(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a tagBelongsToArtifactTx) Clear() error {
	return a.tx.Clear()
}

func (a tagBelongsToArtifactTx) Count() int64 {
	return a.tx.Count()
}

type tagDo struct{ gen.DO }

func (t tagDo) Debug() *tagDo {
	return t.withDO(t.DO.Debug())
}

func (t tagDo) WithContext(ctx context.Context) *tagDo {
	return t.withDO(t.DO.WithContext(ctx))
}

func (t tagDo) ReadDB() *tagDo {
	return t.Clauses(dbresolver.Read)
}

func (t tagDo) WriteDB() *tagDo {
	return t.Clauses(dbresolver.Write)
}

func (t tagDo) Session(config *gorm.Session) *tagDo {
	return t.withDO(t.DO.Session(config))
}

func (t tagDo) Clauses(conds ...clause.Expression) *tagDo {
	return t.withDO(t.DO.Clauses(conds...))
}

func (t tagDo) Returning(value interface{}, columns ...string) *tagDo {
	return t.withDO(t.DO.Returning(value, columns...))
}

func (t tagDo) Not(conds ...gen.Condition) *tagDo {
	return t.withDO(t.DO.Not(conds...))
}

func (t tagDo) Or(conds ...gen.Condition) *tagDo {
	return t.withDO(t.DO.Or(conds...))
}

func (t tagDo) Select(conds ...field.Expr) *tagDo {
	return t.withDO(t.DO.Select(conds...))
}

func (t tagDo) Where(conds ...gen.Condition) *tagDo {
	return t.withDO(t.DO.Where(conds...))
}

func (t tagDo) Order(conds ...field.Expr) *tagDo {
	return t.withDO(t.DO.Order(conds...))
}

func (t tagDo) Distinct(cols ...field.Expr) *tagDo {
	return t.withDO(t.DO.Distinct(cols...))
}

func (t tagDo) Omit(cols ...field.Expr) *tagDo {
	return t.withDO(t.DO.Omit(cols...))
}

func (t tagDo) Join(table schema.Tabler, on ...field.Expr) *tagDo {
	return t.withDO(t.DO.Join(table, on...))
}

func (t tagDo) LeftJoin(table schema.Tabler, on ...field.Expr) *tagDo {
	return t.withDO(t.DO.LeftJoin(table, on...))
}

func (t tagDo) RightJoin(table schema.Tabler, on ...field.Expr) *tagDo {
	return t.withDO(t.DO.RightJoin(table, on...))
}

func (t tagDo) Group(cols ...field.Expr) *tagDo {
	return t.withDO(t.DO.Group(cols...))
}

func (t tagDo) Having(conds ...gen.Condition) *tagDo {
	return t.withDO(t.DO.Having(conds...))
}

func (t tagDo) Limit(limit int) *tagDo {
	return t.withDO(t.DO.Limit(limit))
}

func (t tagDo) Offset(offset int) *tagDo {
	return t.withDO(t.DO.Offset(offset))
}

func (t tagDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *tagDo {
	return t.withDO(t.DO.Scopes(funcs...))
}

func (t tagDo) Unscoped() *tagDo {
	return t.withDO(t.DO.Unscoped())
}

func (t tagDo) Create(values ...*models.Tag) error {
	if len(values) == 0 {
		return nil
	}
	return t.DO.Create(values)
}

func (t tagDo) CreateInBatches(values []*models.Tag, batchSize int) error {
	return t.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (t tagDo) Save(values ...*models.Tag) error {
	if len(values) == 0 {
		return nil
	}
	return t.DO.Save(values)
}

func (t tagDo) First() (*models.Tag, error) {
	if result, err := t.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.Tag), nil
	}
}

func (t tagDo) Take() (*models.Tag, error) {
	if result, err := t.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.Tag), nil
	}
}

func (t tagDo) Last() (*models.Tag, error) {
	if result, err := t.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.Tag), nil
	}
}

func (t tagDo) Find() ([]*models.Tag, error) {
	result, err := t.DO.Find()
	return result.([]*models.Tag), err
}

func (t tagDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.Tag, err error) {
	buf := make([]*models.Tag, 0, batchSize)
	err = t.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (t tagDo) FindInBatches(result *[]*models.Tag, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return t.DO.FindInBatches(result, batchSize, fc)
}

func (t tagDo) Attrs(attrs ...field.AssignExpr) *tagDo {
	return t.withDO(t.DO.Attrs(attrs...))
}

func (t tagDo) Assign(attrs ...field.AssignExpr) *tagDo {
	return t.withDO(t.DO.Assign(attrs...))
}

func (t tagDo) Joins(fields ...field.RelationField) *tagDo {
	for _, _f := range fields {
		t = *t.withDO(t.DO.Joins(_f))
	}
	return &t
}

func (t tagDo) Preload(fields ...field.RelationField) *tagDo {
	for _, _f := range fields {
		t = *t.withDO(t.DO.Preload(_f))
	}
	return &t
}

func (t tagDo) FirstOrInit() (*models.Tag, error) {
	if result, err := t.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.Tag), nil
	}
}

func (t tagDo) FirstOrCreate() (*models.Tag, error) {
	if result, err := t.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.Tag), nil
	}
}

func (t tagDo) FindByPage(offset int, limit int) (result []*models.Tag, count int64, err error) {
	result, err = t.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = t.Offset(-1).Limit(-1).Count()
	return
}

func (t tagDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = t.Count()
	if err != nil {
		return
	}

	err = t.Offset(offset).Limit(limit).Scan(result)
	return
}

func (t tagDo) Scan(result interface{}) (err error) {
	return t.DO.Scan(result)
}

func (t tagDo) Delete(models ...*models.Tag) (result gen.ResultInfo, err error) {
	return t.DO.Delete(models)
}

func (t *tagDo) withDO(do gen.Dao) *tagDo {
	t.DO = *do.(*gen.DO)
	return t
}
