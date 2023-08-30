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

func newCodeRepositoryBranch(db *gorm.DB, opts ...gen.DOOption) codeRepositoryBranch {
	_codeRepositoryBranch := codeRepositoryBranch{}

	_codeRepositoryBranch.codeRepositoryBranchDo.UseDB(db, opts...)
	_codeRepositoryBranch.codeRepositoryBranchDo.UseModel(&models.CodeRepositoryBranch{})

	tableName := _codeRepositoryBranch.codeRepositoryBranchDo.TableName()
	_codeRepositoryBranch.ALL = field.NewAsterisk(tableName)
	_codeRepositoryBranch.CreatedAt = field.NewTime(tableName, "created_at")
	_codeRepositoryBranch.UpdatedAt = field.NewTime(tableName, "updated_at")
	_codeRepositoryBranch.DeletedAt = field.NewUint(tableName, "deleted_at")
	_codeRepositoryBranch.ID = field.NewInt64(tableName, "id")
	_codeRepositoryBranch.CodeRepositoryID = field.NewInt64(tableName, "code_repository_id")
	_codeRepositoryBranch.Name = field.NewString(tableName, "name")

	_codeRepositoryBranch.fillFieldMap()

	return _codeRepositoryBranch
}

type codeRepositoryBranch struct {
	codeRepositoryBranchDo codeRepositoryBranchDo

	ALL              field.Asterisk
	CreatedAt        field.Time
	UpdatedAt        field.Time
	DeletedAt        field.Uint
	ID               field.Int64
	CodeRepositoryID field.Int64
	Name             field.String

	fieldMap map[string]field.Expr
}

func (c codeRepositoryBranch) Table(newTableName string) *codeRepositoryBranch {
	c.codeRepositoryBranchDo.UseTable(newTableName)
	return c.updateTableName(newTableName)
}

func (c codeRepositoryBranch) As(alias string) *codeRepositoryBranch {
	c.codeRepositoryBranchDo.DO = *(c.codeRepositoryBranchDo.As(alias).(*gen.DO))
	return c.updateTableName(alias)
}

func (c *codeRepositoryBranch) updateTableName(table string) *codeRepositoryBranch {
	c.ALL = field.NewAsterisk(table)
	c.CreatedAt = field.NewTime(table, "created_at")
	c.UpdatedAt = field.NewTime(table, "updated_at")
	c.DeletedAt = field.NewUint(table, "deleted_at")
	c.ID = field.NewInt64(table, "id")
	c.CodeRepositoryID = field.NewInt64(table, "code_repository_id")
	c.Name = field.NewString(table, "name")

	c.fillFieldMap()

	return c
}

func (c *codeRepositoryBranch) WithContext(ctx context.Context) *codeRepositoryBranchDo {
	return c.codeRepositoryBranchDo.WithContext(ctx)
}

func (c codeRepositoryBranch) TableName() string { return c.codeRepositoryBranchDo.TableName() }

func (c codeRepositoryBranch) Alias() string { return c.codeRepositoryBranchDo.Alias() }

func (c codeRepositoryBranch) Columns(cols ...field.Expr) gen.Columns {
	return c.codeRepositoryBranchDo.Columns(cols...)
}

func (c *codeRepositoryBranch) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := c.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (c *codeRepositoryBranch) fillFieldMap() {
	c.fieldMap = make(map[string]field.Expr, 6)
	c.fieldMap["created_at"] = c.CreatedAt
	c.fieldMap["updated_at"] = c.UpdatedAt
	c.fieldMap["deleted_at"] = c.DeletedAt
	c.fieldMap["id"] = c.ID
	c.fieldMap["code_repository_id"] = c.CodeRepositoryID
	c.fieldMap["name"] = c.Name
}

func (c codeRepositoryBranch) clone(db *gorm.DB) codeRepositoryBranch {
	c.codeRepositoryBranchDo.ReplaceConnPool(db.Statement.ConnPool)
	return c
}

func (c codeRepositoryBranch) replaceDB(db *gorm.DB) codeRepositoryBranch {
	c.codeRepositoryBranchDo.ReplaceDB(db)
	return c
}

type codeRepositoryBranchDo struct{ gen.DO }

func (c codeRepositoryBranchDo) Debug() *codeRepositoryBranchDo {
	return c.withDO(c.DO.Debug())
}

func (c codeRepositoryBranchDo) WithContext(ctx context.Context) *codeRepositoryBranchDo {
	return c.withDO(c.DO.WithContext(ctx))
}

func (c codeRepositoryBranchDo) ReadDB() *codeRepositoryBranchDo {
	return c.Clauses(dbresolver.Read)
}

func (c codeRepositoryBranchDo) WriteDB() *codeRepositoryBranchDo {
	return c.Clauses(dbresolver.Write)
}

func (c codeRepositoryBranchDo) Session(config *gorm.Session) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Session(config))
}

func (c codeRepositoryBranchDo) Clauses(conds ...clause.Expression) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Clauses(conds...))
}

func (c codeRepositoryBranchDo) Returning(value interface{}, columns ...string) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Returning(value, columns...))
}

func (c codeRepositoryBranchDo) Not(conds ...gen.Condition) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Not(conds...))
}

func (c codeRepositoryBranchDo) Or(conds ...gen.Condition) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Or(conds...))
}

func (c codeRepositoryBranchDo) Select(conds ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Select(conds...))
}

func (c codeRepositoryBranchDo) Where(conds ...gen.Condition) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Where(conds...))
}

func (c codeRepositoryBranchDo) Order(conds ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Order(conds...))
}

func (c codeRepositoryBranchDo) Distinct(cols ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Distinct(cols...))
}

func (c codeRepositoryBranchDo) Omit(cols ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Omit(cols...))
}

func (c codeRepositoryBranchDo) Join(table schema.Tabler, on ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Join(table, on...))
}

func (c codeRepositoryBranchDo) LeftJoin(table schema.Tabler, on ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.LeftJoin(table, on...))
}

func (c codeRepositoryBranchDo) RightJoin(table schema.Tabler, on ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.RightJoin(table, on...))
}

func (c codeRepositoryBranchDo) Group(cols ...field.Expr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Group(cols...))
}

func (c codeRepositoryBranchDo) Having(conds ...gen.Condition) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Having(conds...))
}

func (c codeRepositoryBranchDo) Limit(limit int) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Limit(limit))
}

func (c codeRepositoryBranchDo) Offset(offset int) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Offset(offset))
}

func (c codeRepositoryBranchDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Scopes(funcs...))
}

func (c codeRepositoryBranchDo) Unscoped() *codeRepositoryBranchDo {
	return c.withDO(c.DO.Unscoped())
}

func (c codeRepositoryBranchDo) Create(values ...*models.CodeRepositoryBranch) error {
	if len(values) == 0 {
		return nil
	}
	return c.DO.Create(values)
}

func (c codeRepositoryBranchDo) CreateInBatches(values []*models.CodeRepositoryBranch, batchSize int) error {
	return c.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (c codeRepositoryBranchDo) Save(values ...*models.CodeRepositoryBranch) error {
	if len(values) == 0 {
		return nil
	}
	return c.DO.Save(values)
}

func (c codeRepositoryBranchDo) First() (*models.CodeRepositoryBranch, error) {
	if result, err := c.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepositoryBranch), nil
	}
}

func (c codeRepositoryBranchDo) Take() (*models.CodeRepositoryBranch, error) {
	if result, err := c.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepositoryBranch), nil
	}
}

func (c codeRepositoryBranchDo) Last() (*models.CodeRepositoryBranch, error) {
	if result, err := c.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepositoryBranch), nil
	}
}

func (c codeRepositoryBranchDo) Find() ([]*models.CodeRepositoryBranch, error) {
	result, err := c.DO.Find()
	return result.([]*models.CodeRepositoryBranch), err
}

func (c codeRepositoryBranchDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.CodeRepositoryBranch, err error) {
	buf := make([]*models.CodeRepositoryBranch, 0, batchSize)
	err = c.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (c codeRepositoryBranchDo) FindInBatches(result *[]*models.CodeRepositoryBranch, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return c.DO.FindInBatches(result, batchSize, fc)
}

func (c codeRepositoryBranchDo) Attrs(attrs ...field.AssignExpr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Attrs(attrs...))
}

func (c codeRepositoryBranchDo) Assign(attrs ...field.AssignExpr) *codeRepositoryBranchDo {
	return c.withDO(c.DO.Assign(attrs...))
}

func (c codeRepositoryBranchDo) Joins(fields ...field.RelationField) *codeRepositoryBranchDo {
	for _, _f := range fields {
		c = *c.withDO(c.DO.Joins(_f))
	}
	return &c
}

func (c codeRepositoryBranchDo) Preload(fields ...field.RelationField) *codeRepositoryBranchDo {
	for _, _f := range fields {
		c = *c.withDO(c.DO.Preload(_f))
	}
	return &c
}

func (c codeRepositoryBranchDo) FirstOrInit() (*models.CodeRepositoryBranch, error) {
	if result, err := c.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepositoryBranch), nil
	}
}

func (c codeRepositoryBranchDo) FirstOrCreate() (*models.CodeRepositoryBranch, error) {
	if result, err := c.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepositoryBranch), nil
	}
}

func (c codeRepositoryBranchDo) FindByPage(offset int, limit int) (result []*models.CodeRepositoryBranch, count int64, err error) {
	result, err = c.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = c.Offset(-1).Limit(-1).Count()
	return
}

func (c codeRepositoryBranchDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = c.Count()
	if err != nil {
		return
	}

	err = c.Offset(offset).Limit(limit).Scan(result)
	return
}

func (c codeRepositoryBranchDo) Scan(result interface{}) (err error) {
	return c.DO.Scan(result)
}

func (c codeRepositoryBranchDo) Delete(models ...*models.CodeRepositoryBranch) (result gen.ResultInfo, err error) {
	return c.DO.Delete(models)
}

func (c *codeRepositoryBranchDo) withDO(do gen.Dao) *codeRepositoryBranchDo {
	c.DO = *do.(*gen.DO)
	return c
}
