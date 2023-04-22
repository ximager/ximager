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

	"github.com/ximager/ximager/pkg/dal/models"
)

func newArtifactSbom(db *gorm.DB, opts ...gen.DOOption) artifactSbom {
	_artifactSbom := artifactSbom{}

	_artifactSbom.artifactSbomDo.UseDB(db, opts...)
	_artifactSbom.artifactSbomDo.UseModel(&models.ArtifactSbom{})

	tableName := _artifactSbom.artifactSbomDo.TableName()
	_artifactSbom.ALL = field.NewAsterisk(tableName)
	_artifactSbom.CreatedAt = field.NewTime(tableName, "created_at")
	_artifactSbom.UpdatedAt = field.NewTime(tableName, "updated_at")
	_artifactSbom.DeletedAt = field.NewUint(tableName, "deleted_at")
	_artifactSbom.ID = field.NewUint64(tableName, "id")
	_artifactSbom.ArtifactID = field.NewUint64(tableName, "artifact_id")
	_artifactSbom.Raw = field.NewBytes(tableName, "raw")
	_artifactSbom.Status = field.NewString(tableName, "status")
	_artifactSbom.Stdout = field.NewBytes(tableName, "stdout")
	_artifactSbom.Stderr = field.NewBytes(tableName, "stderr")
	_artifactSbom.Message = field.NewString(tableName, "message")
	_artifactSbom.Artifact = artifactSbomBelongsToArtifact{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Artifact", "models.Artifact"),
		Repository: struct {
			field.RelationField
			Namespace struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Artifact.Repository", "models.Repository"),
			Namespace: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Artifact.Repository.Namespace", "models.Namespace"),
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

	_artifactSbom.fillFieldMap()

	return _artifactSbom
}

type artifactSbom struct {
	artifactSbomDo artifactSbomDo

	ALL        field.Asterisk
	CreatedAt  field.Time
	UpdatedAt  field.Time
	DeletedAt  field.Uint
	ID         field.Uint64
	ArtifactID field.Uint64
	Raw        field.Bytes
	Status     field.String
	Stdout     field.Bytes
	Stderr     field.Bytes
	Message    field.String
	Artifact   artifactSbomBelongsToArtifact

	fieldMap map[string]field.Expr
}

func (a artifactSbom) Table(newTableName string) *artifactSbom {
	a.artifactSbomDo.UseTable(newTableName)
	return a.updateTableName(newTableName)
}

func (a artifactSbom) As(alias string) *artifactSbom {
	a.artifactSbomDo.DO = *(a.artifactSbomDo.As(alias).(*gen.DO))
	return a.updateTableName(alias)
}

func (a *artifactSbom) updateTableName(table string) *artifactSbom {
	a.ALL = field.NewAsterisk(table)
	a.CreatedAt = field.NewTime(table, "created_at")
	a.UpdatedAt = field.NewTime(table, "updated_at")
	a.DeletedAt = field.NewUint(table, "deleted_at")
	a.ID = field.NewUint64(table, "id")
	a.ArtifactID = field.NewUint64(table, "artifact_id")
	a.Raw = field.NewBytes(table, "raw")
	a.Status = field.NewString(table, "status")
	a.Stdout = field.NewBytes(table, "stdout")
	a.Stderr = field.NewBytes(table, "stderr")
	a.Message = field.NewString(table, "message")

	a.fillFieldMap()

	return a
}

func (a *artifactSbom) WithContext(ctx context.Context) *artifactSbomDo {
	return a.artifactSbomDo.WithContext(ctx)
}

func (a artifactSbom) TableName() string { return a.artifactSbomDo.TableName() }

func (a artifactSbom) Alias() string { return a.artifactSbomDo.Alias() }

func (a *artifactSbom) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := a.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (a *artifactSbom) fillFieldMap() {
	a.fieldMap = make(map[string]field.Expr, 11)
	a.fieldMap["created_at"] = a.CreatedAt
	a.fieldMap["updated_at"] = a.UpdatedAt
	a.fieldMap["deleted_at"] = a.DeletedAt
	a.fieldMap["id"] = a.ID
	a.fieldMap["artifact_id"] = a.ArtifactID
	a.fieldMap["raw"] = a.Raw
	a.fieldMap["status"] = a.Status
	a.fieldMap["stdout"] = a.Stdout
	a.fieldMap["stderr"] = a.Stderr
	a.fieldMap["message"] = a.Message

}

func (a artifactSbom) clone(db *gorm.DB) artifactSbom {
	a.artifactSbomDo.ReplaceConnPool(db.Statement.ConnPool)
	return a
}

func (a artifactSbom) replaceDB(db *gorm.DB) artifactSbom {
	a.artifactSbomDo.ReplaceDB(db)
	return a
}

type artifactSbomBelongsToArtifact struct {
	db *gorm.DB

	field.RelationField

	Repository struct {
		field.RelationField
		Namespace struct {
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
	Blobs struct {
		field.RelationField
		Artifacts struct {
			field.RelationField
		}
	}
}

func (a artifactSbomBelongsToArtifact) Where(conds ...field.Expr) *artifactSbomBelongsToArtifact {
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

func (a artifactSbomBelongsToArtifact) WithContext(ctx context.Context) *artifactSbomBelongsToArtifact {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a artifactSbomBelongsToArtifact) Model(m *models.ArtifactSbom) *artifactSbomBelongsToArtifactTx {
	return &artifactSbomBelongsToArtifactTx{a.db.Model(m).Association(a.Name())}
}

type artifactSbomBelongsToArtifactTx struct{ tx *gorm.Association }

func (a artifactSbomBelongsToArtifactTx) Find() (result *models.Artifact, err error) {
	return result, a.tx.Find(&result)
}

func (a artifactSbomBelongsToArtifactTx) Append(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a artifactSbomBelongsToArtifactTx) Replace(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a artifactSbomBelongsToArtifactTx) Delete(values ...*models.Artifact) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a artifactSbomBelongsToArtifactTx) Clear() error {
	return a.tx.Clear()
}

func (a artifactSbomBelongsToArtifactTx) Count() int64 {
	return a.tx.Count()
}

type artifactSbomDo struct{ gen.DO }

func (a artifactSbomDo) Debug() *artifactSbomDo {
	return a.withDO(a.DO.Debug())
}

func (a artifactSbomDo) WithContext(ctx context.Context) *artifactSbomDo {
	return a.withDO(a.DO.WithContext(ctx))
}

func (a artifactSbomDo) ReadDB() *artifactSbomDo {
	return a.Clauses(dbresolver.Read)
}

func (a artifactSbomDo) WriteDB() *artifactSbomDo {
	return a.Clauses(dbresolver.Write)
}

func (a artifactSbomDo) Session(config *gorm.Session) *artifactSbomDo {
	return a.withDO(a.DO.Session(config))
}

func (a artifactSbomDo) Clauses(conds ...clause.Expression) *artifactSbomDo {
	return a.withDO(a.DO.Clauses(conds...))
}

func (a artifactSbomDo) Returning(value interface{}, columns ...string) *artifactSbomDo {
	return a.withDO(a.DO.Returning(value, columns...))
}

func (a artifactSbomDo) Not(conds ...gen.Condition) *artifactSbomDo {
	return a.withDO(a.DO.Not(conds...))
}

func (a artifactSbomDo) Or(conds ...gen.Condition) *artifactSbomDo {
	return a.withDO(a.DO.Or(conds...))
}

func (a artifactSbomDo) Select(conds ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Select(conds...))
}

func (a artifactSbomDo) Where(conds ...gen.Condition) *artifactSbomDo {
	return a.withDO(a.DO.Where(conds...))
}

func (a artifactSbomDo) Exists(subquery interface{ UnderlyingDB() *gorm.DB }) *artifactSbomDo {
	return a.Where(field.CompareSubQuery(field.ExistsOp, nil, subquery.UnderlyingDB()))
}

func (a artifactSbomDo) Order(conds ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Order(conds...))
}

func (a artifactSbomDo) Distinct(cols ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Distinct(cols...))
}

func (a artifactSbomDo) Omit(cols ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Omit(cols...))
}

func (a artifactSbomDo) Join(table schema.Tabler, on ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Join(table, on...))
}

func (a artifactSbomDo) LeftJoin(table schema.Tabler, on ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.LeftJoin(table, on...))
}

func (a artifactSbomDo) RightJoin(table schema.Tabler, on ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.RightJoin(table, on...))
}

func (a artifactSbomDo) Group(cols ...field.Expr) *artifactSbomDo {
	return a.withDO(a.DO.Group(cols...))
}

func (a artifactSbomDo) Having(conds ...gen.Condition) *artifactSbomDo {
	return a.withDO(a.DO.Having(conds...))
}

func (a artifactSbomDo) Limit(limit int) *artifactSbomDo {
	return a.withDO(a.DO.Limit(limit))
}

func (a artifactSbomDo) Offset(offset int) *artifactSbomDo {
	return a.withDO(a.DO.Offset(offset))
}

func (a artifactSbomDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *artifactSbomDo {
	return a.withDO(a.DO.Scopes(funcs...))
}

func (a artifactSbomDo) Unscoped() *artifactSbomDo {
	return a.withDO(a.DO.Unscoped())
}

func (a artifactSbomDo) Create(values ...*models.ArtifactSbom) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Create(values)
}

func (a artifactSbomDo) CreateInBatches(values []*models.ArtifactSbom, batchSize int) error {
	return a.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (a artifactSbomDo) Save(values ...*models.ArtifactSbom) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Save(values)
}

func (a artifactSbomDo) First() (*models.ArtifactSbom, error) {
	if result, err := a.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.ArtifactSbom), nil
	}
}

func (a artifactSbomDo) Take() (*models.ArtifactSbom, error) {
	if result, err := a.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.ArtifactSbom), nil
	}
}

func (a artifactSbomDo) Last() (*models.ArtifactSbom, error) {
	if result, err := a.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.ArtifactSbom), nil
	}
}

func (a artifactSbomDo) Find() ([]*models.ArtifactSbom, error) {
	result, err := a.DO.Find()
	return result.([]*models.ArtifactSbom), err
}

func (a artifactSbomDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.ArtifactSbom, err error) {
	buf := make([]*models.ArtifactSbom, 0, batchSize)
	err = a.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (a artifactSbomDo) FindInBatches(result *[]*models.ArtifactSbom, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return a.DO.FindInBatches(result, batchSize, fc)
}

func (a artifactSbomDo) Attrs(attrs ...field.AssignExpr) *artifactSbomDo {
	return a.withDO(a.DO.Attrs(attrs...))
}

func (a artifactSbomDo) Assign(attrs ...field.AssignExpr) *artifactSbomDo {
	return a.withDO(a.DO.Assign(attrs...))
}

func (a artifactSbomDo) Joins(fields ...field.RelationField) *artifactSbomDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Joins(_f))
	}
	return &a
}

func (a artifactSbomDo) Preload(fields ...field.RelationField) *artifactSbomDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Preload(_f))
	}
	return &a
}

func (a artifactSbomDo) FirstOrInit() (*models.ArtifactSbom, error) {
	if result, err := a.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.ArtifactSbom), nil
	}
}

func (a artifactSbomDo) FirstOrCreate() (*models.ArtifactSbom, error) {
	if result, err := a.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.ArtifactSbom), nil
	}
}

func (a artifactSbomDo) FindByPage(offset int, limit int) (result []*models.ArtifactSbom, count int64, err error) {
	result, err = a.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = a.Offset(-1).Limit(-1).Count()
	return
}

func (a artifactSbomDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = a.Count()
	if err != nil {
		return
	}

	err = a.Offset(offset).Limit(limit).Scan(result)
	return
}

func (a artifactSbomDo) Scan(result interface{}) (err error) {
	return a.DO.Scan(result)
}

func (a artifactSbomDo) Delete(models ...*models.ArtifactSbom) (result gen.ResultInfo, err error) {
	return a.DO.Delete(models)
}

func (a *artifactSbomDo) withDO(do gen.Dao) *artifactSbomDo {
	a.DO = *do.(*gen.DO)
	return a
}
