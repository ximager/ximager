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

func newDaemonGcBlobRecord(db *gorm.DB, opts ...gen.DOOption) daemonGcBlobRecord {
	_daemonGcBlobRecord := daemonGcBlobRecord{}

	_daemonGcBlobRecord.daemonGcBlobRecordDo.UseDB(db, opts...)
	_daemonGcBlobRecord.daemonGcBlobRecordDo.UseModel(&models.DaemonGcBlobRecord{})

	tableName := _daemonGcBlobRecord.daemonGcBlobRecordDo.TableName()
	_daemonGcBlobRecord.ALL = field.NewAsterisk(tableName)
	_daemonGcBlobRecord.CreatedAt = field.NewTime(tableName, "created_at")
	_daemonGcBlobRecord.UpdatedAt = field.NewTime(tableName, "updated_at")
	_daemonGcBlobRecord.DeletedAt = field.NewUint(tableName, "deleted_at")
	_daemonGcBlobRecord.ID = field.NewInt64(tableName, "id")
	_daemonGcBlobRecord.RunnerID = field.NewInt64(tableName, "runner_id")
	_daemonGcBlobRecord.Digest = field.NewString(tableName, "digest")
	_daemonGcBlobRecord.Runner = daemonGcBlobRecordBelongsToRunner{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Runner", "models.DaemonGcBlobRunner"),
		Rule: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Runner.Rule", "models.DaemonGcBlobRule"),
		},
	}

	_daemonGcBlobRecord.fillFieldMap()

	return _daemonGcBlobRecord
}

type daemonGcBlobRecord struct {
	daemonGcBlobRecordDo daemonGcBlobRecordDo

	ALL       field.Asterisk
	CreatedAt field.Time
	UpdatedAt field.Time
	DeletedAt field.Uint
	ID        field.Int64
	RunnerID  field.Int64
	Digest    field.String
	Runner    daemonGcBlobRecordBelongsToRunner

	fieldMap map[string]field.Expr
}

func (d daemonGcBlobRecord) Table(newTableName string) *daemonGcBlobRecord {
	d.daemonGcBlobRecordDo.UseTable(newTableName)
	return d.updateTableName(newTableName)
}

func (d daemonGcBlobRecord) As(alias string) *daemonGcBlobRecord {
	d.daemonGcBlobRecordDo.DO = *(d.daemonGcBlobRecordDo.As(alias).(*gen.DO))
	return d.updateTableName(alias)
}

func (d *daemonGcBlobRecord) updateTableName(table string) *daemonGcBlobRecord {
	d.ALL = field.NewAsterisk(table)
	d.CreatedAt = field.NewTime(table, "created_at")
	d.UpdatedAt = field.NewTime(table, "updated_at")
	d.DeletedAt = field.NewUint(table, "deleted_at")
	d.ID = field.NewInt64(table, "id")
	d.RunnerID = field.NewInt64(table, "runner_id")
	d.Digest = field.NewString(table, "digest")

	d.fillFieldMap()

	return d
}

func (d *daemonGcBlobRecord) WithContext(ctx context.Context) *daemonGcBlobRecordDo {
	return d.daemonGcBlobRecordDo.WithContext(ctx)
}

func (d daemonGcBlobRecord) TableName() string { return d.daemonGcBlobRecordDo.TableName() }

func (d daemonGcBlobRecord) Alias() string { return d.daemonGcBlobRecordDo.Alias() }

func (d daemonGcBlobRecord) Columns(cols ...field.Expr) gen.Columns {
	return d.daemonGcBlobRecordDo.Columns(cols...)
}

func (d *daemonGcBlobRecord) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := d.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (d *daemonGcBlobRecord) fillFieldMap() {
	d.fieldMap = make(map[string]field.Expr, 7)
	d.fieldMap["created_at"] = d.CreatedAt
	d.fieldMap["updated_at"] = d.UpdatedAt
	d.fieldMap["deleted_at"] = d.DeletedAt
	d.fieldMap["id"] = d.ID
	d.fieldMap["runner_id"] = d.RunnerID
	d.fieldMap["digest"] = d.Digest

}

func (d daemonGcBlobRecord) clone(db *gorm.DB) daemonGcBlobRecord {
	d.daemonGcBlobRecordDo.ReplaceConnPool(db.Statement.ConnPool)
	return d
}

func (d daemonGcBlobRecord) replaceDB(db *gorm.DB) daemonGcBlobRecord {
	d.daemonGcBlobRecordDo.ReplaceDB(db)
	return d
}

type daemonGcBlobRecordBelongsToRunner struct {
	db *gorm.DB

	field.RelationField

	Rule struct {
		field.RelationField
	}
}

func (a daemonGcBlobRecordBelongsToRunner) Where(conds ...field.Expr) *daemonGcBlobRecordBelongsToRunner {
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

func (a daemonGcBlobRecordBelongsToRunner) WithContext(ctx context.Context) *daemonGcBlobRecordBelongsToRunner {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a daemonGcBlobRecordBelongsToRunner) Session(session *gorm.Session) *daemonGcBlobRecordBelongsToRunner {
	a.db = a.db.Session(session)
	return &a
}

func (a daemonGcBlobRecordBelongsToRunner) Model(m *models.DaemonGcBlobRecord) *daemonGcBlobRecordBelongsToRunnerTx {
	return &daemonGcBlobRecordBelongsToRunnerTx{a.db.Model(m).Association(a.Name())}
}

type daemonGcBlobRecordBelongsToRunnerTx struct{ tx *gorm.Association }

func (a daemonGcBlobRecordBelongsToRunnerTx) Find() (result *models.DaemonGcBlobRunner, err error) {
	return result, a.tx.Find(&result)
}

func (a daemonGcBlobRecordBelongsToRunnerTx) Append(values ...*models.DaemonGcBlobRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a daemonGcBlobRecordBelongsToRunnerTx) Replace(values ...*models.DaemonGcBlobRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a daemonGcBlobRecordBelongsToRunnerTx) Delete(values ...*models.DaemonGcBlobRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a daemonGcBlobRecordBelongsToRunnerTx) Clear() error {
	return a.tx.Clear()
}

func (a daemonGcBlobRecordBelongsToRunnerTx) Count() int64 {
	return a.tx.Count()
}

type daemonGcBlobRecordDo struct{ gen.DO }

func (d daemonGcBlobRecordDo) Debug() *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Debug())
}

func (d daemonGcBlobRecordDo) WithContext(ctx context.Context) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.WithContext(ctx))
}

func (d daemonGcBlobRecordDo) ReadDB() *daemonGcBlobRecordDo {
	return d.Clauses(dbresolver.Read)
}

func (d daemonGcBlobRecordDo) WriteDB() *daemonGcBlobRecordDo {
	return d.Clauses(dbresolver.Write)
}

func (d daemonGcBlobRecordDo) Session(config *gorm.Session) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Session(config))
}

func (d daemonGcBlobRecordDo) Clauses(conds ...clause.Expression) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Clauses(conds...))
}

func (d daemonGcBlobRecordDo) Returning(value interface{}, columns ...string) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Returning(value, columns...))
}

func (d daemonGcBlobRecordDo) Not(conds ...gen.Condition) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Not(conds...))
}

func (d daemonGcBlobRecordDo) Or(conds ...gen.Condition) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Or(conds...))
}

func (d daemonGcBlobRecordDo) Select(conds ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Select(conds...))
}

func (d daemonGcBlobRecordDo) Where(conds ...gen.Condition) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Where(conds...))
}

func (d daemonGcBlobRecordDo) Order(conds ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Order(conds...))
}

func (d daemonGcBlobRecordDo) Distinct(cols ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Distinct(cols...))
}

func (d daemonGcBlobRecordDo) Omit(cols ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Omit(cols...))
}

func (d daemonGcBlobRecordDo) Join(table schema.Tabler, on ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Join(table, on...))
}

func (d daemonGcBlobRecordDo) LeftJoin(table schema.Tabler, on ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.LeftJoin(table, on...))
}

func (d daemonGcBlobRecordDo) RightJoin(table schema.Tabler, on ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.RightJoin(table, on...))
}

func (d daemonGcBlobRecordDo) Group(cols ...field.Expr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Group(cols...))
}

func (d daemonGcBlobRecordDo) Having(conds ...gen.Condition) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Having(conds...))
}

func (d daemonGcBlobRecordDo) Limit(limit int) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Limit(limit))
}

func (d daemonGcBlobRecordDo) Offset(offset int) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Offset(offset))
}

func (d daemonGcBlobRecordDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Scopes(funcs...))
}

func (d daemonGcBlobRecordDo) Unscoped() *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Unscoped())
}

func (d daemonGcBlobRecordDo) Create(values ...*models.DaemonGcBlobRecord) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Create(values)
}

func (d daemonGcBlobRecordDo) CreateInBatches(values []*models.DaemonGcBlobRecord, batchSize int) error {
	return d.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (d daemonGcBlobRecordDo) Save(values ...*models.DaemonGcBlobRecord) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Save(values)
}

func (d daemonGcBlobRecordDo) First() (*models.DaemonGcBlobRecord, error) {
	if result, err := d.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcBlobRecord), nil
	}
}

func (d daemonGcBlobRecordDo) Take() (*models.DaemonGcBlobRecord, error) {
	if result, err := d.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcBlobRecord), nil
	}
}

func (d daemonGcBlobRecordDo) Last() (*models.DaemonGcBlobRecord, error) {
	if result, err := d.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcBlobRecord), nil
	}
}

func (d daemonGcBlobRecordDo) Find() ([]*models.DaemonGcBlobRecord, error) {
	result, err := d.DO.Find()
	return result.([]*models.DaemonGcBlobRecord), err
}

func (d daemonGcBlobRecordDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.DaemonGcBlobRecord, err error) {
	buf := make([]*models.DaemonGcBlobRecord, 0, batchSize)
	err = d.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (d daemonGcBlobRecordDo) FindInBatches(result *[]*models.DaemonGcBlobRecord, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return d.DO.FindInBatches(result, batchSize, fc)
}

func (d daemonGcBlobRecordDo) Attrs(attrs ...field.AssignExpr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Attrs(attrs...))
}

func (d daemonGcBlobRecordDo) Assign(attrs ...field.AssignExpr) *daemonGcBlobRecordDo {
	return d.withDO(d.DO.Assign(attrs...))
}

func (d daemonGcBlobRecordDo) Joins(fields ...field.RelationField) *daemonGcBlobRecordDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Joins(_f))
	}
	return &d
}

func (d daemonGcBlobRecordDo) Preload(fields ...field.RelationField) *daemonGcBlobRecordDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Preload(_f))
	}
	return &d
}

func (d daemonGcBlobRecordDo) FirstOrInit() (*models.DaemonGcBlobRecord, error) {
	if result, err := d.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcBlobRecord), nil
	}
}

func (d daemonGcBlobRecordDo) FirstOrCreate() (*models.DaemonGcBlobRecord, error) {
	if result, err := d.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcBlobRecord), nil
	}
}

func (d daemonGcBlobRecordDo) FindByPage(offset int, limit int) (result []*models.DaemonGcBlobRecord, count int64, err error) {
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

func (d daemonGcBlobRecordDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = d.Count()
	if err != nil {
		return
	}

	err = d.Offset(offset).Limit(limit).Scan(result)
	return
}

func (d daemonGcBlobRecordDo) Scan(result interface{}) (err error) {
	return d.DO.Scan(result)
}

func (d daemonGcBlobRecordDo) Delete(models ...*models.DaemonGcBlobRecord) (result gen.ResultInfo, err error) {
	return d.DO.Delete(models)
}

func (d *daemonGcBlobRecordDo) withDO(do gen.Dao) *daemonGcBlobRecordDo {
	d.DO = *do.(*gen.DO)
	return d
}
