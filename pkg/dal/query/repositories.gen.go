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

func newRepository(db *gorm.DB, opts ...gen.DOOption) repository {
	_repository := repository{}

	_repository.repositoryDo.UseDB(db, opts...)
	_repository.repositoryDo.UseModel(&models.Repository{})

	tableName := _repository.repositoryDo.TableName()
	_repository.ALL = field.NewAsterisk(tableName)
	_repository.CreatedAt = field.NewTime(tableName, "created_at")
	_repository.UpdatedAt = field.NewTime(tableName, "updated_at")
	_repository.DeletedAt = field.NewUint(tableName, "deleted_at")
	_repository.ID = field.NewInt64(tableName, "id")
	_repository.NamespaceID = field.NewInt64(tableName, "namespace_id")
	_repository.Name = field.NewString(tableName, "name")
	_repository.Description = field.NewString(tableName, "description")
	_repository.Overview = field.NewBytes(tableName, "overview")
	_repository.Visibility = field.NewField(tableName, "visibility")
	_repository.TagLimit = field.NewInt64(tableName, "tag_limit")
	_repository.TagCount = field.NewInt64(tableName, "tag_count")
	_repository.SizeLimit = field.NewInt64(tableName, "size_limit")
	_repository.Size = field.NewInt64(tableName, "size")
	_repository.Builder = repositoryHasOneBuilder{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Builder", "models.Builder"),
		Repository: struct {
			field.RelationField
			Namespace struct {
				field.RelationField
			}
			Builder struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Builder.Repository", "models.Repository"),
			Namespace: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Builder.Repository.Namespace", "models.Namespace"),
			},
			Builder: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Builder.Repository.Builder", "models.Builder"),
			},
		},
	}

	_repository.Namespace = repositoryBelongsToNamespace{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Namespace", "models.Namespace"),
	}

	_repository.fillFieldMap()

	return _repository
}

type repository struct {
	repositoryDo repositoryDo

	ALL         field.Asterisk
	CreatedAt   field.Time
	UpdatedAt   field.Time
	DeletedAt   field.Uint
	ID          field.Int64
	NamespaceID field.Int64
	Name        field.String
	Description field.String
	Overview    field.Bytes
	Visibility  field.Field
	TagLimit    field.Int64
	TagCount    field.Int64
	SizeLimit   field.Int64
	Size        field.Int64
	Builder     repositoryHasOneBuilder

	Namespace repositoryBelongsToNamespace

	fieldMap map[string]field.Expr
}

func (r repository) Table(newTableName string) *repository {
	r.repositoryDo.UseTable(newTableName)
	return r.updateTableName(newTableName)
}

func (r repository) As(alias string) *repository {
	r.repositoryDo.DO = *(r.repositoryDo.As(alias).(*gen.DO))
	return r.updateTableName(alias)
}

func (r *repository) updateTableName(table string) *repository {
	r.ALL = field.NewAsterisk(table)
	r.CreatedAt = field.NewTime(table, "created_at")
	r.UpdatedAt = field.NewTime(table, "updated_at")
	r.DeletedAt = field.NewUint(table, "deleted_at")
	r.ID = field.NewInt64(table, "id")
	r.NamespaceID = field.NewInt64(table, "namespace_id")
	r.Name = field.NewString(table, "name")
	r.Description = field.NewString(table, "description")
	r.Overview = field.NewBytes(table, "overview")
	r.Visibility = field.NewField(table, "visibility")
	r.TagLimit = field.NewInt64(table, "tag_limit")
	r.TagCount = field.NewInt64(table, "tag_count")
	r.SizeLimit = field.NewInt64(table, "size_limit")
	r.Size = field.NewInt64(table, "size")

	r.fillFieldMap()

	return r
}

func (r *repository) WithContext(ctx context.Context) *repositoryDo {
	return r.repositoryDo.WithContext(ctx)
}

func (r repository) TableName() string { return r.repositoryDo.TableName() }

func (r repository) Alias() string { return r.repositoryDo.Alias() }

func (r repository) Columns(cols ...field.Expr) gen.Columns { return r.repositoryDo.Columns(cols...) }

func (r *repository) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := r.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (r *repository) fillFieldMap() {
	r.fieldMap = make(map[string]field.Expr, 15)
	r.fieldMap["created_at"] = r.CreatedAt
	r.fieldMap["updated_at"] = r.UpdatedAt
	r.fieldMap["deleted_at"] = r.DeletedAt
	r.fieldMap["id"] = r.ID
	r.fieldMap["namespace_id"] = r.NamespaceID
	r.fieldMap["name"] = r.Name
	r.fieldMap["description"] = r.Description
	r.fieldMap["overview"] = r.Overview
	r.fieldMap["visibility"] = r.Visibility
	r.fieldMap["tag_limit"] = r.TagLimit
	r.fieldMap["tag_count"] = r.TagCount
	r.fieldMap["size_limit"] = r.SizeLimit
	r.fieldMap["size"] = r.Size

}

func (r repository) clone(db *gorm.DB) repository {
	r.repositoryDo.ReplaceConnPool(db.Statement.ConnPool)
	return r
}

func (r repository) replaceDB(db *gorm.DB) repository {
	r.repositoryDo.ReplaceDB(db)
	return r
}

type repositoryHasOneBuilder struct {
	db *gorm.DB

	field.RelationField

	Repository struct {
		field.RelationField
		Namespace struct {
			field.RelationField
		}
		Builder struct {
			field.RelationField
		}
	}
}

func (a repositoryHasOneBuilder) Where(conds ...field.Expr) *repositoryHasOneBuilder {
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

func (a repositoryHasOneBuilder) WithContext(ctx context.Context) *repositoryHasOneBuilder {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a repositoryHasOneBuilder) Session(session *gorm.Session) *repositoryHasOneBuilder {
	a.db = a.db.Session(session)
	return &a
}

func (a repositoryHasOneBuilder) Model(m *models.Repository) *repositoryHasOneBuilderTx {
	return &repositoryHasOneBuilderTx{a.db.Model(m).Association(a.Name())}
}

type repositoryHasOneBuilderTx struct{ tx *gorm.Association }

func (a repositoryHasOneBuilderTx) Find() (result *models.Builder, err error) {
	return result, a.tx.Find(&result)
}

func (a repositoryHasOneBuilderTx) Append(values ...*models.Builder) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a repositoryHasOneBuilderTx) Replace(values ...*models.Builder) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a repositoryHasOneBuilderTx) Delete(values ...*models.Builder) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a repositoryHasOneBuilderTx) Clear() error {
	return a.tx.Clear()
}

func (a repositoryHasOneBuilderTx) Count() int64 {
	return a.tx.Count()
}

type repositoryBelongsToNamespace struct {
	db *gorm.DB

	field.RelationField
}

func (a repositoryBelongsToNamespace) Where(conds ...field.Expr) *repositoryBelongsToNamespace {
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

func (a repositoryBelongsToNamespace) WithContext(ctx context.Context) *repositoryBelongsToNamespace {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a repositoryBelongsToNamespace) Session(session *gorm.Session) *repositoryBelongsToNamespace {
	a.db = a.db.Session(session)
	return &a
}

func (a repositoryBelongsToNamespace) Model(m *models.Repository) *repositoryBelongsToNamespaceTx {
	return &repositoryBelongsToNamespaceTx{a.db.Model(m).Association(a.Name())}
}

type repositoryBelongsToNamespaceTx struct{ tx *gorm.Association }

func (a repositoryBelongsToNamespaceTx) Find() (result *models.Namespace, err error) {
	return result, a.tx.Find(&result)
}

func (a repositoryBelongsToNamespaceTx) Append(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a repositoryBelongsToNamespaceTx) Replace(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a repositoryBelongsToNamespaceTx) Delete(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a repositoryBelongsToNamespaceTx) Clear() error {
	return a.tx.Clear()
}

func (a repositoryBelongsToNamespaceTx) Count() int64 {
	return a.tx.Count()
}

type repositoryDo struct{ gen.DO }

func (r repositoryDo) Debug() *repositoryDo {
	return r.withDO(r.DO.Debug())
}

func (r repositoryDo) WithContext(ctx context.Context) *repositoryDo {
	return r.withDO(r.DO.WithContext(ctx))
}

func (r repositoryDo) ReadDB() *repositoryDo {
	return r.Clauses(dbresolver.Read)
}

func (r repositoryDo) WriteDB() *repositoryDo {
	return r.Clauses(dbresolver.Write)
}

func (r repositoryDo) Session(config *gorm.Session) *repositoryDo {
	return r.withDO(r.DO.Session(config))
}

func (r repositoryDo) Clauses(conds ...clause.Expression) *repositoryDo {
	return r.withDO(r.DO.Clauses(conds...))
}

func (r repositoryDo) Returning(value interface{}, columns ...string) *repositoryDo {
	return r.withDO(r.DO.Returning(value, columns...))
}

func (r repositoryDo) Not(conds ...gen.Condition) *repositoryDo {
	return r.withDO(r.DO.Not(conds...))
}

func (r repositoryDo) Or(conds ...gen.Condition) *repositoryDo {
	return r.withDO(r.DO.Or(conds...))
}

func (r repositoryDo) Select(conds ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Select(conds...))
}

func (r repositoryDo) Where(conds ...gen.Condition) *repositoryDo {
	return r.withDO(r.DO.Where(conds...))
}

func (r repositoryDo) Order(conds ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Order(conds...))
}

func (r repositoryDo) Distinct(cols ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Distinct(cols...))
}

func (r repositoryDo) Omit(cols ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Omit(cols...))
}

func (r repositoryDo) Join(table schema.Tabler, on ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Join(table, on...))
}

func (r repositoryDo) LeftJoin(table schema.Tabler, on ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.LeftJoin(table, on...))
}

func (r repositoryDo) RightJoin(table schema.Tabler, on ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.RightJoin(table, on...))
}

func (r repositoryDo) Group(cols ...field.Expr) *repositoryDo {
	return r.withDO(r.DO.Group(cols...))
}

func (r repositoryDo) Having(conds ...gen.Condition) *repositoryDo {
	return r.withDO(r.DO.Having(conds...))
}

func (r repositoryDo) Limit(limit int) *repositoryDo {
	return r.withDO(r.DO.Limit(limit))
}

func (r repositoryDo) Offset(offset int) *repositoryDo {
	return r.withDO(r.DO.Offset(offset))
}

func (r repositoryDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *repositoryDo {
	return r.withDO(r.DO.Scopes(funcs...))
}

func (r repositoryDo) Unscoped() *repositoryDo {
	return r.withDO(r.DO.Unscoped())
}

func (r repositoryDo) Create(values ...*models.Repository) error {
	if len(values) == 0 {
		return nil
	}
	return r.DO.Create(values)
}

func (r repositoryDo) CreateInBatches(values []*models.Repository, batchSize int) error {
	return r.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (r repositoryDo) Save(values ...*models.Repository) error {
	if len(values) == 0 {
		return nil
	}
	return r.DO.Save(values)
}

func (r repositoryDo) First() (*models.Repository, error) {
	if result, err := r.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.Repository), nil
	}
}

func (r repositoryDo) Take() (*models.Repository, error) {
	if result, err := r.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.Repository), nil
	}
}

func (r repositoryDo) Last() (*models.Repository, error) {
	if result, err := r.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.Repository), nil
	}
}

func (r repositoryDo) Find() ([]*models.Repository, error) {
	result, err := r.DO.Find()
	return result.([]*models.Repository), err
}

func (r repositoryDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.Repository, err error) {
	buf := make([]*models.Repository, 0, batchSize)
	err = r.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (r repositoryDo) FindInBatches(result *[]*models.Repository, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return r.DO.FindInBatches(result, batchSize, fc)
}

func (r repositoryDo) Attrs(attrs ...field.AssignExpr) *repositoryDo {
	return r.withDO(r.DO.Attrs(attrs...))
}

func (r repositoryDo) Assign(attrs ...field.AssignExpr) *repositoryDo {
	return r.withDO(r.DO.Assign(attrs...))
}

func (r repositoryDo) Joins(fields ...field.RelationField) *repositoryDo {
	for _, _f := range fields {
		r = *r.withDO(r.DO.Joins(_f))
	}
	return &r
}

func (r repositoryDo) Preload(fields ...field.RelationField) *repositoryDo {
	for _, _f := range fields {
		r = *r.withDO(r.DO.Preload(_f))
	}
	return &r
}

func (r repositoryDo) FirstOrInit() (*models.Repository, error) {
	if result, err := r.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.Repository), nil
	}
}

func (r repositoryDo) FirstOrCreate() (*models.Repository, error) {
	if result, err := r.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.Repository), nil
	}
}

func (r repositoryDo) FindByPage(offset int, limit int) (result []*models.Repository, count int64, err error) {
	result, err = r.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = r.Offset(-1).Limit(-1).Count()
	return
}

func (r repositoryDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = r.Count()
	if err != nil {
		return
	}

	err = r.Offset(offset).Limit(limit).Scan(result)
	return
}

func (r repositoryDo) Scan(result interface{}) (err error) {
	return r.DO.Scan(result)
}

func (r repositoryDo) Delete(models ...*models.Repository) (result gen.ResultInfo, err error) {
	return r.DO.Delete(models)
}

func (r *repositoryDo) withDO(do gen.Dao) *repositoryDo {
	r.DO = *do.(*gen.DO)
	return r
}
