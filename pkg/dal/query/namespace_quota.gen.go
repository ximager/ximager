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

func newNamespaceQuota(db *gorm.DB, opts ...gen.DOOption) namespaceQuota {
	_namespaceQuota := namespaceQuota{}

	_namespaceQuota.namespaceQuotaDo.UseDB(db, opts...)
	_namespaceQuota.namespaceQuotaDo.UseModel(&models.NamespaceQuota{})

	tableName := _namespaceQuota.namespaceQuotaDo.TableName()
	_namespaceQuota.ALL = field.NewAsterisk(tableName)
	_namespaceQuota.CreatedAt = field.NewTime(tableName, "created_at")
	_namespaceQuota.UpdatedAt = field.NewTime(tableName, "updated_at")
	_namespaceQuota.DeletedAt = field.NewUint(tableName, "deleted_at")
	_namespaceQuota.ID = field.NewInt64(tableName, "id")
	_namespaceQuota.NamespaceID = field.NewInt64(tableName, "namespace_id")
	_namespaceQuota.Limit = field.NewInt64(tableName, "limit")
	_namespaceQuota.Usage = field.NewInt64(tableName, "usage")

	_namespaceQuota.fillFieldMap()

	return _namespaceQuota
}

type namespaceQuota struct {
	namespaceQuotaDo namespaceQuotaDo

	ALL         field.Asterisk
	CreatedAt   field.Time
	UpdatedAt   field.Time
	DeletedAt   field.Uint
	ID          field.Int64
	NamespaceID field.Int64
	Limit       field.Int64
	Usage       field.Int64

	fieldMap map[string]field.Expr
}

func (n namespaceQuota) Table(newTableName string) *namespaceQuota {
	n.namespaceQuotaDo.UseTable(newTableName)
	return n.updateTableName(newTableName)
}

func (n namespaceQuota) As(alias string) *namespaceQuota {
	n.namespaceQuotaDo.DO = *(n.namespaceQuotaDo.As(alias).(*gen.DO))
	return n.updateTableName(alias)
}

func (n *namespaceQuota) updateTableName(table string) *namespaceQuota {
	n.ALL = field.NewAsterisk(table)
	n.CreatedAt = field.NewTime(table, "created_at")
	n.UpdatedAt = field.NewTime(table, "updated_at")
	n.DeletedAt = field.NewUint(table, "deleted_at")
	n.ID = field.NewInt64(table, "id")
	n.NamespaceID = field.NewInt64(table, "namespace_id")
	n.Limit = field.NewInt64(table, "limit")
	n.Usage = field.NewInt64(table, "usage")

	n.fillFieldMap()

	return n
}

func (n *namespaceQuota) WithContext(ctx context.Context) *namespaceQuotaDo {
	return n.namespaceQuotaDo.WithContext(ctx)
}

func (n namespaceQuota) TableName() string { return n.namespaceQuotaDo.TableName() }

func (n namespaceQuota) Alias() string { return n.namespaceQuotaDo.Alias() }

func (n *namespaceQuota) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := n.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (n *namespaceQuota) fillFieldMap() {
	n.fieldMap = make(map[string]field.Expr, 7)
	n.fieldMap["created_at"] = n.CreatedAt
	n.fieldMap["updated_at"] = n.UpdatedAt
	n.fieldMap["deleted_at"] = n.DeletedAt
	n.fieldMap["id"] = n.ID
	n.fieldMap["namespace_id"] = n.NamespaceID
	n.fieldMap["limit"] = n.Limit
	n.fieldMap["usage"] = n.Usage
}

func (n namespaceQuota) clone(db *gorm.DB) namespaceQuota {
	n.namespaceQuotaDo.ReplaceConnPool(db.Statement.ConnPool)
	return n
}

func (n namespaceQuota) replaceDB(db *gorm.DB) namespaceQuota {
	n.namespaceQuotaDo.ReplaceDB(db)
	return n
}

type namespaceQuotaDo struct{ gen.DO }

func (n namespaceQuotaDo) Debug() *namespaceQuotaDo {
	return n.withDO(n.DO.Debug())
}

func (n namespaceQuotaDo) WithContext(ctx context.Context) *namespaceQuotaDo {
	return n.withDO(n.DO.WithContext(ctx))
}

func (n namespaceQuotaDo) ReadDB() *namespaceQuotaDo {
	return n.Clauses(dbresolver.Read)
}

func (n namespaceQuotaDo) WriteDB() *namespaceQuotaDo {
	return n.Clauses(dbresolver.Write)
}

func (n namespaceQuotaDo) Session(config *gorm.Session) *namespaceQuotaDo {
	return n.withDO(n.DO.Session(config))
}

func (n namespaceQuotaDo) Clauses(conds ...clause.Expression) *namespaceQuotaDo {
	return n.withDO(n.DO.Clauses(conds...))
}

func (n namespaceQuotaDo) Returning(value interface{}, columns ...string) *namespaceQuotaDo {
	return n.withDO(n.DO.Returning(value, columns...))
}

func (n namespaceQuotaDo) Not(conds ...gen.Condition) *namespaceQuotaDo {
	return n.withDO(n.DO.Not(conds...))
}

func (n namespaceQuotaDo) Or(conds ...gen.Condition) *namespaceQuotaDo {
	return n.withDO(n.DO.Or(conds...))
}

func (n namespaceQuotaDo) Select(conds ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Select(conds...))
}

func (n namespaceQuotaDo) Where(conds ...gen.Condition) *namespaceQuotaDo {
	return n.withDO(n.DO.Where(conds...))
}

func (n namespaceQuotaDo) Exists(subquery interface{ UnderlyingDB() *gorm.DB }) *namespaceQuotaDo {
	return n.Where(field.CompareSubQuery(field.ExistsOp, nil, subquery.UnderlyingDB()))
}

func (n namespaceQuotaDo) Order(conds ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Order(conds...))
}

func (n namespaceQuotaDo) Distinct(cols ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Distinct(cols...))
}

func (n namespaceQuotaDo) Omit(cols ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Omit(cols...))
}

func (n namespaceQuotaDo) Join(table schema.Tabler, on ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Join(table, on...))
}

func (n namespaceQuotaDo) LeftJoin(table schema.Tabler, on ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.LeftJoin(table, on...))
}

func (n namespaceQuotaDo) RightJoin(table schema.Tabler, on ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.RightJoin(table, on...))
}

func (n namespaceQuotaDo) Group(cols ...field.Expr) *namespaceQuotaDo {
	return n.withDO(n.DO.Group(cols...))
}

func (n namespaceQuotaDo) Having(conds ...gen.Condition) *namespaceQuotaDo {
	return n.withDO(n.DO.Having(conds...))
}

func (n namespaceQuotaDo) Limit(limit int) *namespaceQuotaDo {
	return n.withDO(n.DO.Limit(limit))
}

func (n namespaceQuotaDo) Offset(offset int) *namespaceQuotaDo {
	return n.withDO(n.DO.Offset(offset))
}

func (n namespaceQuotaDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *namespaceQuotaDo {
	return n.withDO(n.DO.Scopes(funcs...))
}

func (n namespaceQuotaDo) Unscoped() *namespaceQuotaDo {
	return n.withDO(n.DO.Unscoped())
}

func (n namespaceQuotaDo) Create(values ...*models.NamespaceQuota) error {
	if len(values) == 0 {
		return nil
	}
	return n.DO.Create(values)
}

func (n namespaceQuotaDo) CreateInBatches(values []*models.NamespaceQuota, batchSize int) error {
	return n.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (n namespaceQuotaDo) Save(values ...*models.NamespaceQuota) error {
	if len(values) == 0 {
		return nil
	}
	return n.DO.Save(values)
}

func (n namespaceQuotaDo) First() (*models.NamespaceQuota, error) {
	if result, err := n.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.NamespaceQuota), nil
	}
}

func (n namespaceQuotaDo) Take() (*models.NamespaceQuota, error) {
	if result, err := n.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.NamespaceQuota), nil
	}
}

func (n namespaceQuotaDo) Last() (*models.NamespaceQuota, error) {
	if result, err := n.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.NamespaceQuota), nil
	}
}

func (n namespaceQuotaDo) Find() ([]*models.NamespaceQuota, error) {
	result, err := n.DO.Find()
	return result.([]*models.NamespaceQuota), err
}

func (n namespaceQuotaDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.NamespaceQuota, err error) {
	buf := make([]*models.NamespaceQuota, 0, batchSize)
	err = n.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (n namespaceQuotaDo) FindInBatches(result *[]*models.NamespaceQuota, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return n.DO.FindInBatches(result, batchSize, fc)
}

func (n namespaceQuotaDo) Attrs(attrs ...field.AssignExpr) *namespaceQuotaDo {
	return n.withDO(n.DO.Attrs(attrs...))
}

func (n namespaceQuotaDo) Assign(attrs ...field.AssignExpr) *namespaceQuotaDo {
	return n.withDO(n.DO.Assign(attrs...))
}

func (n namespaceQuotaDo) Joins(fields ...field.RelationField) *namespaceQuotaDo {
	for _, _f := range fields {
		n = *n.withDO(n.DO.Joins(_f))
	}
	return &n
}

func (n namespaceQuotaDo) Preload(fields ...field.RelationField) *namespaceQuotaDo {
	for _, _f := range fields {
		n = *n.withDO(n.DO.Preload(_f))
	}
	return &n
}

func (n namespaceQuotaDo) FirstOrInit() (*models.NamespaceQuota, error) {
	if result, err := n.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.NamespaceQuota), nil
	}
}

func (n namespaceQuotaDo) FirstOrCreate() (*models.NamespaceQuota, error) {
	if result, err := n.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.NamespaceQuota), nil
	}
}

func (n namespaceQuotaDo) FindByPage(offset int, limit int) (result []*models.NamespaceQuota, count int64, err error) {
	result, err = n.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = n.Offset(-1).Limit(-1).Count()
	return
}

func (n namespaceQuotaDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = n.Count()
	if err != nil {
		return
	}

	err = n.Offset(offset).Limit(limit).Scan(result)
	return
}

func (n namespaceQuotaDo) Scan(result interface{}) (err error) {
	return n.DO.Scan(result)
}

func (n namespaceQuotaDo) Delete(models ...*models.NamespaceQuota) (result gen.ResultInfo, err error) {
	return n.DO.Delete(models)
}

func (n *namespaceQuotaDo) withDO(do gen.Dao) *namespaceQuotaDo {
	n.DO = *do.(*gen.DO)
	return n
}
