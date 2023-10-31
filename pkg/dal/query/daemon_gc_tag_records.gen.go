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

func newDaemonGcTagRecord(db *gorm.DB, opts ...gen.DOOption) daemonGcTagRecord {
	_daemonGcTagRecord := daemonGcTagRecord{}

	_daemonGcTagRecord.daemonGcTagRecordDo.UseDB(db, opts...)
	_daemonGcTagRecord.daemonGcTagRecordDo.UseModel(&models.DaemonGcTagRecord{})

	tableName := _daemonGcTagRecord.daemonGcTagRecordDo.TableName()
	_daemonGcTagRecord.ALL = field.NewAsterisk(tableName)
	_daemonGcTagRecord.CreatedAt = field.NewTime(tableName, "created_at")
	_daemonGcTagRecord.UpdatedAt = field.NewTime(tableName, "updated_at")
	_daemonGcTagRecord.DeletedAt = field.NewUint(tableName, "deleted_at")
	_daemonGcTagRecord.ID = field.NewInt64(tableName, "id")
	_daemonGcTagRecord.RunnerID = field.NewInt64(tableName, "runner_id")
	_daemonGcTagRecord.Tag = field.NewString(tableName, "tag")
	_daemonGcTagRecord.Runner = daemonGcTagRecordBelongsToRunner{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Runner", "models.DaemonGcTagRunner"),
		Rule: struct {
			field.RelationField
			Namespace struct {
				field.RelationField
			}
		}{
			RelationField: field.NewRelation("Runner.Rule", "models.DaemonGcTagRule"),
			Namespace: struct {
				field.RelationField
			}{
				RelationField: field.NewRelation("Runner.Rule.Namespace", "models.Namespace"),
			},
		},
	}

	_daemonGcTagRecord.fillFieldMap()

	return _daemonGcTagRecord
}

type daemonGcTagRecord struct {
	daemonGcTagRecordDo daemonGcTagRecordDo

	ALL       field.Asterisk
	CreatedAt field.Time
	UpdatedAt field.Time
	DeletedAt field.Uint
	ID        field.Int64
	RunnerID  field.Int64
	Tag       field.String
	Runner    daemonGcTagRecordBelongsToRunner

	fieldMap map[string]field.Expr
}

func (d daemonGcTagRecord) Table(newTableName string) *daemonGcTagRecord {
	d.daemonGcTagRecordDo.UseTable(newTableName)
	return d.updateTableName(newTableName)
}

func (d daemonGcTagRecord) As(alias string) *daemonGcTagRecord {
	d.daemonGcTagRecordDo.DO = *(d.daemonGcTagRecordDo.As(alias).(*gen.DO))
	return d.updateTableName(alias)
}

func (d *daemonGcTagRecord) updateTableName(table string) *daemonGcTagRecord {
	d.ALL = field.NewAsterisk(table)
	d.CreatedAt = field.NewTime(table, "created_at")
	d.UpdatedAt = field.NewTime(table, "updated_at")
	d.DeletedAt = field.NewUint(table, "deleted_at")
	d.ID = field.NewInt64(table, "id")
	d.RunnerID = field.NewInt64(table, "runner_id")
	d.Tag = field.NewString(table, "tag")

	d.fillFieldMap()

	return d
}

func (d *daemonGcTagRecord) WithContext(ctx context.Context) *daemonGcTagRecordDo {
	return d.daemonGcTagRecordDo.WithContext(ctx)
}

func (d daemonGcTagRecord) TableName() string { return d.daemonGcTagRecordDo.TableName() }

func (d daemonGcTagRecord) Alias() string { return d.daemonGcTagRecordDo.Alias() }

func (d daemonGcTagRecord) Columns(cols ...field.Expr) gen.Columns {
	return d.daemonGcTagRecordDo.Columns(cols...)
}

func (d *daemonGcTagRecord) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := d.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (d *daemonGcTagRecord) fillFieldMap() {
	d.fieldMap = make(map[string]field.Expr, 7)
	d.fieldMap["created_at"] = d.CreatedAt
	d.fieldMap["updated_at"] = d.UpdatedAt
	d.fieldMap["deleted_at"] = d.DeletedAt
	d.fieldMap["id"] = d.ID
	d.fieldMap["runner_id"] = d.RunnerID
	d.fieldMap["tag"] = d.Tag

}

func (d daemonGcTagRecord) clone(db *gorm.DB) daemonGcTagRecord {
	d.daemonGcTagRecordDo.ReplaceConnPool(db.Statement.ConnPool)
	return d
}

func (d daemonGcTagRecord) replaceDB(db *gorm.DB) daemonGcTagRecord {
	d.daemonGcTagRecordDo.ReplaceDB(db)
	return d
}

type daemonGcTagRecordBelongsToRunner struct {
	db *gorm.DB

	field.RelationField

	Rule struct {
		field.RelationField
		Namespace struct {
			field.RelationField
		}
	}
}

func (a daemonGcTagRecordBelongsToRunner) Where(conds ...field.Expr) *daemonGcTagRecordBelongsToRunner {
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

func (a daemonGcTagRecordBelongsToRunner) WithContext(ctx context.Context) *daemonGcTagRecordBelongsToRunner {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a daemonGcTagRecordBelongsToRunner) Session(session *gorm.Session) *daemonGcTagRecordBelongsToRunner {
	a.db = a.db.Session(session)
	return &a
}

func (a daemonGcTagRecordBelongsToRunner) Model(m *models.DaemonGcTagRecord) *daemonGcTagRecordBelongsToRunnerTx {
	return &daemonGcTagRecordBelongsToRunnerTx{a.db.Model(m).Association(a.Name())}
}

type daemonGcTagRecordBelongsToRunnerTx struct{ tx *gorm.Association }

func (a daemonGcTagRecordBelongsToRunnerTx) Find() (result *models.DaemonGcTagRunner, err error) {
	return result, a.tx.Find(&result)
}

func (a daemonGcTagRecordBelongsToRunnerTx) Append(values ...*models.DaemonGcTagRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a daemonGcTagRecordBelongsToRunnerTx) Replace(values ...*models.DaemonGcTagRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a daemonGcTagRecordBelongsToRunnerTx) Delete(values ...*models.DaemonGcTagRunner) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a daemonGcTagRecordBelongsToRunnerTx) Clear() error {
	return a.tx.Clear()
}

func (a daemonGcTagRecordBelongsToRunnerTx) Count() int64 {
	return a.tx.Count()
}

type daemonGcTagRecordDo struct{ gen.DO }

func (d daemonGcTagRecordDo) Debug() *daemonGcTagRecordDo {
	return d.withDO(d.DO.Debug())
}

func (d daemonGcTagRecordDo) WithContext(ctx context.Context) *daemonGcTagRecordDo {
	return d.withDO(d.DO.WithContext(ctx))
}

func (d daemonGcTagRecordDo) ReadDB() *daemonGcTagRecordDo {
	return d.Clauses(dbresolver.Read)
}

func (d daemonGcTagRecordDo) WriteDB() *daemonGcTagRecordDo {
	return d.Clauses(dbresolver.Write)
}

func (d daemonGcTagRecordDo) Session(config *gorm.Session) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Session(config))
}

func (d daemonGcTagRecordDo) Clauses(conds ...clause.Expression) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Clauses(conds...))
}

func (d daemonGcTagRecordDo) Returning(value interface{}, columns ...string) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Returning(value, columns...))
}

func (d daemonGcTagRecordDo) Not(conds ...gen.Condition) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Not(conds...))
}

func (d daemonGcTagRecordDo) Or(conds ...gen.Condition) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Or(conds...))
}

func (d daemonGcTagRecordDo) Select(conds ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Select(conds...))
}

func (d daemonGcTagRecordDo) Where(conds ...gen.Condition) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Where(conds...))
}

func (d daemonGcTagRecordDo) Order(conds ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Order(conds...))
}

func (d daemonGcTagRecordDo) Distinct(cols ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Distinct(cols...))
}

func (d daemonGcTagRecordDo) Omit(cols ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Omit(cols...))
}

func (d daemonGcTagRecordDo) Join(table schema.Tabler, on ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Join(table, on...))
}

func (d daemonGcTagRecordDo) LeftJoin(table schema.Tabler, on ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.LeftJoin(table, on...))
}

func (d daemonGcTagRecordDo) RightJoin(table schema.Tabler, on ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.RightJoin(table, on...))
}

func (d daemonGcTagRecordDo) Group(cols ...field.Expr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Group(cols...))
}

func (d daemonGcTagRecordDo) Having(conds ...gen.Condition) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Having(conds...))
}

func (d daemonGcTagRecordDo) Limit(limit int) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Limit(limit))
}

func (d daemonGcTagRecordDo) Offset(offset int) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Offset(offset))
}

func (d daemonGcTagRecordDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Scopes(funcs...))
}

func (d daemonGcTagRecordDo) Unscoped() *daemonGcTagRecordDo {
	return d.withDO(d.DO.Unscoped())
}

func (d daemonGcTagRecordDo) Create(values ...*models.DaemonGcTagRecord) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Create(values)
}

func (d daemonGcTagRecordDo) CreateInBatches(values []*models.DaemonGcTagRecord, batchSize int) error {
	return d.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (d daemonGcTagRecordDo) Save(values ...*models.DaemonGcTagRecord) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Save(values)
}

func (d daemonGcTagRecordDo) First() (*models.DaemonGcTagRecord, error) {
	if result, err := d.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRecord), nil
	}
}

func (d daemonGcTagRecordDo) Take() (*models.DaemonGcTagRecord, error) {
	if result, err := d.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRecord), nil
	}
}

func (d daemonGcTagRecordDo) Last() (*models.DaemonGcTagRecord, error) {
	if result, err := d.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRecord), nil
	}
}

func (d daemonGcTagRecordDo) Find() ([]*models.DaemonGcTagRecord, error) {
	result, err := d.DO.Find()
	return result.([]*models.DaemonGcTagRecord), err
}

func (d daemonGcTagRecordDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.DaemonGcTagRecord, err error) {
	buf := make([]*models.DaemonGcTagRecord, 0, batchSize)
	err = d.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (d daemonGcTagRecordDo) FindInBatches(result *[]*models.DaemonGcTagRecord, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return d.DO.FindInBatches(result, batchSize, fc)
}

func (d daemonGcTagRecordDo) Attrs(attrs ...field.AssignExpr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Attrs(attrs...))
}

func (d daemonGcTagRecordDo) Assign(attrs ...field.AssignExpr) *daemonGcTagRecordDo {
	return d.withDO(d.DO.Assign(attrs...))
}

func (d daemonGcTagRecordDo) Joins(fields ...field.RelationField) *daemonGcTagRecordDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Joins(_f))
	}
	return &d
}

func (d daemonGcTagRecordDo) Preload(fields ...field.RelationField) *daemonGcTagRecordDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Preload(_f))
	}
	return &d
}

func (d daemonGcTagRecordDo) FirstOrInit() (*models.DaemonGcTagRecord, error) {
	if result, err := d.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRecord), nil
	}
}

func (d daemonGcTagRecordDo) FirstOrCreate() (*models.DaemonGcTagRecord, error) {
	if result, err := d.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRecord), nil
	}
}

func (d daemonGcTagRecordDo) FindByPage(offset int, limit int) (result []*models.DaemonGcTagRecord, count int64, err error) {
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

func (d daemonGcTagRecordDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = d.Count()
	if err != nil {
		return
	}

	err = d.Offset(offset).Limit(limit).Scan(result)
	return
}

func (d daemonGcTagRecordDo) Scan(result interface{}) (err error) {
	return d.DO.Scan(result)
}

func (d daemonGcTagRecordDo) Delete(models ...*models.DaemonGcTagRecord) (result gen.ResultInfo, err error) {
	return d.DO.Delete(models)
}

func (d *daemonGcTagRecordDo) withDO(do gen.Dao) *daemonGcTagRecordDo {
	d.DO = *do.(*gen.DO)
	return d
}
