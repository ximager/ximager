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

func newDaemonGcArtifactRunner(db *gorm.DB, opts ...gen.DOOption) daemonGcArtifactRunner {
	_daemonGcArtifactRunner := daemonGcArtifactRunner{}

	_daemonGcArtifactRunner.daemonGcArtifactRunnerDo.UseDB(db, opts...)
	_daemonGcArtifactRunner.daemonGcArtifactRunnerDo.UseModel(&models.DaemonGcArtifactRunner{})

	tableName := _daemonGcArtifactRunner.daemonGcArtifactRunnerDo.TableName()
	_daemonGcArtifactRunner.ALL = field.NewAsterisk(tableName)
	_daemonGcArtifactRunner.CreatedAt = field.NewTime(tableName, "created_at")
	_daemonGcArtifactRunner.UpdatedAt = field.NewTime(tableName, "updated_at")
	_daemonGcArtifactRunner.DeletedAt = field.NewUint(tableName, "deleted_at")
	_daemonGcArtifactRunner.ID = field.NewInt64(tableName, "id")
	_daemonGcArtifactRunner.Status = field.NewField(tableName, "status")
	_daemonGcArtifactRunner.Message = field.NewBytes(tableName, "message")
	_daemonGcArtifactRunner.NamespaceID = field.NewInt64(tableName, "namespace_id")
	_daemonGcArtifactRunner.StartedAt = field.NewTime(tableName, "started_at")
	_daemonGcArtifactRunner.EndedAt = field.NewTime(tableName, "ended_at")
	_daemonGcArtifactRunner.Duration = field.NewInt64(tableName, "duration")
	_daemonGcArtifactRunner.Namespace = daemonGcArtifactRunnerBelongsToNamespace{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Namespace", "models.Namespace"),
	}

	_daemonGcArtifactRunner.fillFieldMap()

	return _daemonGcArtifactRunner
}

type daemonGcArtifactRunner struct {
	daemonGcArtifactRunnerDo daemonGcArtifactRunnerDo

	ALL         field.Asterisk
	CreatedAt   field.Time
	UpdatedAt   field.Time
	DeletedAt   field.Uint
	ID          field.Int64
	Status      field.Field
	Message     field.Bytes
	NamespaceID field.Int64
	StartedAt   field.Time
	EndedAt     field.Time
	Duration    field.Int64
	Namespace   daemonGcArtifactRunnerBelongsToNamespace

	fieldMap map[string]field.Expr
}

func (d daemonGcArtifactRunner) Table(newTableName string) *daemonGcArtifactRunner {
	d.daemonGcArtifactRunnerDo.UseTable(newTableName)
	return d.updateTableName(newTableName)
}

func (d daemonGcArtifactRunner) As(alias string) *daemonGcArtifactRunner {
	d.daemonGcArtifactRunnerDo.DO = *(d.daemonGcArtifactRunnerDo.As(alias).(*gen.DO))
	return d.updateTableName(alias)
}

func (d *daemonGcArtifactRunner) updateTableName(table string) *daemonGcArtifactRunner {
	d.ALL = field.NewAsterisk(table)
	d.CreatedAt = field.NewTime(table, "created_at")
	d.UpdatedAt = field.NewTime(table, "updated_at")
	d.DeletedAt = field.NewUint(table, "deleted_at")
	d.ID = field.NewInt64(table, "id")
	d.Status = field.NewField(table, "status")
	d.Message = field.NewBytes(table, "message")
	d.NamespaceID = field.NewInt64(table, "namespace_id")
	d.StartedAt = field.NewTime(table, "started_at")
	d.EndedAt = field.NewTime(table, "ended_at")
	d.Duration = field.NewInt64(table, "duration")

	d.fillFieldMap()

	return d
}

func (d *daemonGcArtifactRunner) WithContext(ctx context.Context) *daemonGcArtifactRunnerDo {
	return d.daemonGcArtifactRunnerDo.WithContext(ctx)
}

func (d daemonGcArtifactRunner) TableName() string { return d.daemonGcArtifactRunnerDo.TableName() }

func (d daemonGcArtifactRunner) Alias() string { return d.daemonGcArtifactRunnerDo.Alias() }

func (d daemonGcArtifactRunner) Columns(cols ...field.Expr) gen.Columns {
	return d.daemonGcArtifactRunnerDo.Columns(cols...)
}

func (d *daemonGcArtifactRunner) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := d.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (d *daemonGcArtifactRunner) fillFieldMap() {
	d.fieldMap = make(map[string]field.Expr, 11)
	d.fieldMap["created_at"] = d.CreatedAt
	d.fieldMap["updated_at"] = d.UpdatedAt
	d.fieldMap["deleted_at"] = d.DeletedAt
	d.fieldMap["id"] = d.ID
	d.fieldMap["status"] = d.Status
	d.fieldMap["message"] = d.Message
	d.fieldMap["namespace_id"] = d.NamespaceID
	d.fieldMap["started_at"] = d.StartedAt
	d.fieldMap["ended_at"] = d.EndedAt
	d.fieldMap["duration"] = d.Duration

}

func (d daemonGcArtifactRunner) clone(db *gorm.DB) daemonGcArtifactRunner {
	d.daemonGcArtifactRunnerDo.ReplaceConnPool(db.Statement.ConnPool)
	return d
}

func (d daemonGcArtifactRunner) replaceDB(db *gorm.DB) daemonGcArtifactRunner {
	d.daemonGcArtifactRunnerDo.ReplaceDB(db)
	return d
}

type daemonGcArtifactRunnerBelongsToNamespace struct {
	db *gorm.DB

	field.RelationField
}

func (a daemonGcArtifactRunnerBelongsToNamespace) Where(conds ...field.Expr) *daemonGcArtifactRunnerBelongsToNamespace {
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

func (a daemonGcArtifactRunnerBelongsToNamespace) WithContext(ctx context.Context) *daemonGcArtifactRunnerBelongsToNamespace {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a daemonGcArtifactRunnerBelongsToNamespace) Session(session *gorm.Session) *daemonGcArtifactRunnerBelongsToNamespace {
	a.db = a.db.Session(session)
	return &a
}

func (a daemonGcArtifactRunnerBelongsToNamespace) Model(m *models.DaemonGcArtifactRunner) *daemonGcArtifactRunnerBelongsToNamespaceTx {
	return &daemonGcArtifactRunnerBelongsToNamespaceTx{a.db.Model(m).Association(a.Name())}
}

type daemonGcArtifactRunnerBelongsToNamespaceTx struct{ tx *gorm.Association }

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Find() (result *models.Namespace, err error) {
	return result, a.tx.Find(&result)
}

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Append(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Replace(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Delete(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Clear() error {
	return a.tx.Clear()
}

func (a daemonGcArtifactRunnerBelongsToNamespaceTx) Count() int64 {
	return a.tx.Count()
}

type daemonGcArtifactRunnerDo struct{ gen.DO }

func (d daemonGcArtifactRunnerDo) Debug() *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Debug())
}

func (d daemonGcArtifactRunnerDo) WithContext(ctx context.Context) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.WithContext(ctx))
}

func (d daemonGcArtifactRunnerDo) ReadDB() *daemonGcArtifactRunnerDo {
	return d.Clauses(dbresolver.Read)
}

func (d daemonGcArtifactRunnerDo) WriteDB() *daemonGcArtifactRunnerDo {
	return d.Clauses(dbresolver.Write)
}

func (d daemonGcArtifactRunnerDo) Session(config *gorm.Session) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Session(config))
}

func (d daemonGcArtifactRunnerDo) Clauses(conds ...clause.Expression) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Clauses(conds...))
}

func (d daemonGcArtifactRunnerDo) Returning(value interface{}, columns ...string) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Returning(value, columns...))
}

func (d daemonGcArtifactRunnerDo) Not(conds ...gen.Condition) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Not(conds...))
}

func (d daemonGcArtifactRunnerDo) Or(conds ...gen.Condition) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Or(conds...))
}

func (d daemonGcArtifactRunnerDo) Select(conds ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Select(conds...))
}

func (d daemonGcArtifactRunnerDo) Where(conds ...gen.Condition) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Where(conds...))
}

func (d daemonGcArtifactRunnerDo) Order(conds ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Order(conds...))
}

func (d daemonGcArtifactRunnerDo) Distinct(cols ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Distinct(cols...))
}

func (d daemonGcArtifactRunnerDo) Omit(cols ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Omit(cols...))
}

func (d daemonGcArtifactRunnerDo) Join(table schema.Tabler, on ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Join(table, on...))
}

func (d daemonGcArtifactRunnerDo) LeftJoin(table schema.Tabler, on ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.LeftJoin(table, on...))
}

func (d daemonGcArtifactRunnerDo) RightJoin(table schema.Tabler, on ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.RightJoin(table, on...))
}

func (d daemonGcArtifactRunnerDo) Group(cols ...field.Expr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Group(cols...))
}

func (d daemonGcArtifactRunnerDo) Having(conds ...gen.Condition) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Having(conds...))
}

func (d daemonGcArtifactRunnerDo) Limit(limit int) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Limit(limit))
}

func (d daemonGcArtifactRunnerDo) Offset(offset int) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Offset(offset))
}

func (d daemonGcArtifactRunnerDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Scopes(funcs...))
}

func (d daemonGcArtifactRunnerDo) Unscoped() *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Unscoped())
}

func (d daemonGcArtifactRunnerDo) Create(values ...*models.DaemonGcArtifactRunner) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Create(values)
}

func (d daemonGcArtifactRunnerDo) CreateInBatches(values []*models.DaemonGcArtifactRunner, batchSize int) error {
	return d.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (d daemonGcArtifactRunnerDo) Save(values ...*models.DaemonGcArtifactRunner) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Save(values)
}

func (d daemonGcArtifactRunnerDo) First() (*models.DaemonGcArtifactRunner, error) {
	if result, err := d.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcArtifactRunner), nil
	}
}

func (d daemonGcArtifactRunnerDo) Take() (*models.DaemonGcArtifactRunner, error) {
	if result, err := d.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcArtifactRunner), nil
	}
}

func (d daemonGcArtifactRunnerDo) Last() (*models.DaemonGcArtifactRunner, error) {
	if result, err := d.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcArtifactRunner), nil
	}
}

func (d daemonGcArtifactRunnerDo) Find() ([]*models.DaemonGcArtifactRunner, error) {
	result, err := d.DO.Find()
	return result.([]*models.DaemonGcArtifactRunner), err
}

func (d daemonGcArtifactRunnerDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.DaemonGcArtifactRunner, err error) {
	buf := make([]*models.DaemonGcArtifactRunner, 0, batchSize)
	err = d.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (d daemonGcArtifactRunnerDo) FindInBatches(result *[]*models.DaemonGcArtifactRunner, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return d.DO.FindInBatches(result, batchSize, fc)
}

func (d daemonGcArtifactRunnerDo) Attrs(attrs ...field.AssignExpr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Attrs(attrs...))
}

func (d daemonGcArtifactRunnerDo) Assign(attrs ...field.AssignExpr) *daemonGcArtifactRunnerDo {
	return d.withDO(d.DO.Assign(attrs...))
}

func (d daemonGcArtifactRunnerDo) Joins(fields ...field.RelationField) *daemonGcArtifactRunnerDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Joins(_f))
	}
	return &d
}

func (d daemonGcArtifactRunnerDo) Preload(fields ...field.RelationField) *daemonGcArtifactRunnerDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Preload(_f))
	}
	return &d
}

func (d daemonGcArtifactRunnerDo) FirstOrInit() (*models.DaemonGcArtifactRunner, error) {
	if result, err := d.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcArtifactRunner), nil
	}
}

func (d daemonGcArtifactRunnerDo) FirstOrCreate() (*models.DaemonGcArtifactRunner, error) {
	if result, err := d.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcArtifactRunner), nil
	}
}

func (d daemonGcArtifactRunnerDo) FindByPage(offset int, limit int) (result []*models.DaemonGcArtifactRunner, count int64, err error) {
	result, err = d.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = d.Offset(-1).Limit(-1).Count()
	return
}

func (d daemonGcArtifactRunnerDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = d.Count()
	if err != nil {
		return
	}

	err = d.Offset(offset).Limit(limit).Scan(result)
	return
}

func (d daemonGcArtifactRunnerDo) Scan(result interface{}) (err error) {
	return d.DO.Scan(result)
}

func (d daemonGcArtifactRunnerDo) Delete(models ...*models.DaemonGcArtifactRunner) (result gen.ResultInfo, err error) {
	return d.DO.Delete(models)
}

func (d *daemonGcArtifactRunnerDo) withDO(do gen.Dao) *daemonGcArtifactRunnerDo {
	d.DO = *do.(*gen.DO)
	return d
}
