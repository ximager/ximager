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

func newDaemonGcTagRunner(db *gorm.DB, opts ...gen.DOOption) daemonGcTagRunner {
	_daemonGcTagRunner := daemonGcTagRunner{}

	_daemonGcTagRunner.daemonGcTagRunnerDo.UseDB(db, opts...)
	_daemonGcTagRunner.daemonGcTagRunnerDo.UseModel(&models.DaemonGcTagRunner{})

	tableName := _daemonGcTagRunner.daemonGcTagRunnerDo.TableName()
	_daemonGcTagRunner.ALL = field.NewAsterisk(tableName)
	_daemonGcTagRunner.CreatedAt = field.NewTime(tableName, "created_at")
	_daemonGcTagRunner.UpdatedAt = field.NewTime(tableName, "updated_at")
	_daemonGcTagRunner.DeletedAt = field.NewUint(tableName, "deleted_at")
	_daemonGcTagRunner.ID = field.NewInt64(tableName, "id")
	_daemonGcTagRunner.RuleID = field.NewInt64(tableName, "rule_id")
	_daemonGcTagRunner.Message = field.NewBytes(tableName, "message")
	_daemonGcTagRunner.Status = field.NewField(tableName, "status")
	_daemonGcTagRunner.StartedAt = field.NewTime(tableName, "started_at")
	_daemonGcTagRunner.EndedAt = field.NewTime(tableName, "ended_at")
	_daemonGcTagRunner.Duration = field.NewInt64(tableName, "duration")
	_daemonGcTagRunner.Rule = daemonGcTagRunnerBelongsToRule{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Rule", "models.DaemonGcTagRule"),
		Namespace: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("Rule.Namespace", "models.Namespace"),
		},
	}

	_daemonGcTagRunner.fillFieldMap()

	return _daemonGcTagRunner
}

type daemonGcTagRunner struct {
	daemonGcTagRunnerDo daemonGcTagRunnerDo

	ALL       field.Asterisk
	CreatedAt field.Time
	UpdatedAt field.Time
	DeletedAt field.Uint
	ID        field.Int64
	RuleID    field.Int64
	Message   field.Bytes
	Status    field.Field
	StartedAt field.Time
	EndedAt   field.Time
	Duration  field.Int64
	Rule      daemonGcTagRunnerBelongsToRule

	fieldMap map[string]field.Expr
}

func (d daemonGcTagRunner) Table(newTableName string) *daemonGcTagRunner {
	d.daemonGcTagRunnerDo.UseTable(newTableName)
	return d.updateTableName(newTableName)
}

func (d daemonGcTagRunner) As(alias string) *daemonGcTagRunner {
	d.daemonGcTagRunnerDo.DO = *(d.daemonGcTagRunnerDo.As(alias).(*gen.DO))
	return d.updateTableName(alias)
}

func (d *daemonGcTagRunner) updateTableName(table string) *daemonGcTagRunner {
	d.ALL = field.NewAsterisk(table)
	d.CreatedAt = field.NewTime(table, "created_at")
	d.UpdatedAt = field.NewTime(table, "updated_at")
	d.DeletedAt = field.NewUint(table, "deleted_at")
	d.ID = field.NewInt64(table, "id")
	d.RuleID = field.NewInt64(table, "rule_id")
	d.Message = field.NewBytes(table, "message")
	d.Status = field.NewField(table, "status")
	d.StartedAt = field.NewTime(table, "started_at")
	d.EndedAt = field.NewTime(table, "ended_at")
	d.Duration = field.NewInt64(table, "duration")

	d.fillFieldMap()

	return d
}

func (d *daemonGcTagRunner) WithContext(ctx context.Context) *daemonGcTagRunnerDo {
	return d.daemonGcTagRunnerDo.WithContext(ctx)
}

func (d daemonGcTagRunner) TableName() string { return d.daemonGcTagRunnerDo.TableName() }

func (d daemonGcTagRunner) Alias() string { return d.daemonGcTagRunnerDo.Alias() }

func (d daemonGcTagRunner) Columns(cols ...field.Expr) gen.Columns {
	return d.daemonGcTagRunnerDo.Columns(cols...)
}

func (d *daemonGcTagRunner) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := d.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (d *daemonGcTagRunner) fillFieldMap() {
	d.fieldMap = make(map[string]field.Expr, 11)
	d.fieldMap["created_at"] = d.CreatedAt
	d.fieldMap["updated_at"] = d.UpdatedAt
	d.fieldMap["deleted_at"] = d.DeletedAt
	d.fieldMap["id"] = d.ID
	d.fieldMap["rule_id"] = d.RuleID
	d.fieldMap["message"] = d.Message
	d.fieldMap["status"] = d.Status
	d.fieldMap["started_at"] = d.StartedAt
	d.fieldMap["ended_at"] = d.EndedAt
	d.fieldMap["duration"] = d.Duration

}

func (d daemonGcTagRunner) clone(db *gorm.DB) daemonGcTagRunner {
	d.daemonGcTagRunnerDo.ReplaceConnPool(db.Statement.ConnPool)
	return d
}

func (d daemonGcTagRunner) replaceDB(db *gorm.DB) daemonGcTagRunner {
	d.daemonGcTagRunnerDo.ReplaceDB(db)
	return d
}

type daemonGcTagRunnerBelongsToRule struct {
	db *gorm.DB

	field.RelationField

	Namespace struct {
		field.RelationField
	}
}

func (a daemonGcTagRunnerBelongsToRule) Where(conds ...field.Expr) *daemonGcTagRunnerBelongsToRule {
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

func (a daemonGcTagRunnerBelongsToRule) WithContext(ctx context.Context) *daemonGcTagRunnerBelongsToRule {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a daemonGcTagRunnerBelongsToRule) Session(session *gorm.Session) *daemonGcTagRunnerBelongsToRule {
	a.db = a.db.Session(session)
	return &a
}

func (a daemonGcTagRunnerBelongsToRule) Model(m *models.DaemonGcTagRunner) *daemonGcTagRunnerBelongsToRuleTx {
	return &daemonGcTagRunnerBelongsToRuleTx{a.db.Model(m).Association(a.Name())}
}

type daemonGcTagRunnerBelongsToRuleTx struct{ tx *gorm.Association }

func (a daemonGcTagRunnerBelongsToRuleTx) Find() (result *models.DaemonGcTagRule, err error) {
	return result, a.tx.Find(&result)
}

func (a daemonGcTagRunnerBelongsToRuleTx) Append(values ...*models.DaemonGcTagRule) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a daemonGcTagRunnerBelongsToRuleTx) Replace(values ...*models.DaemonGcTagRule) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a daemonGcTagRunnerBelongsToRuleTx) Delete(values ...*models.DaemonGcTagRule) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a daemonGcTagRunnerBelongsToRuleTx) Clear() error {
	return a.tx.Clear()
}

func (a daemonGcTagRunnerBelongsToRuleTx) Count() int64 {
	return a.tx.Count()
}

type daemonGcTagRunnerDo struct{ gen.DO }

func (d daemonGcTagRunnerDo) Debug() *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Debug())
}

func (d daemonGcTagRunnerDo) WithContext(ctx context.Context) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.WithContext(ctx))
}

func (d daemonGcTagRunnerDo) ReadDB() *daemonGcTagRunnerDo {
	return d.Clauses(dbresolver.Read)
}

func (d daemonGcTagRunnerDo) WriteDB() *daemonGcTagRunnerDo {
	return d.Clauses(dbresolver.Write)
}

func (d daemonGcTagRunnerDo) Session(config *gorm.Session) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Session(config))
}

func (d daemonGcTagRunnerDo) Clauses(conds ...clause.Expression) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Clauses(conds...))
}

func (d daemonGcTagRunnerDo) Returning(value interface{}, columns ...string) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Returning(value, columns...))
}

func (d daemonGcTagRunnerDo) Not(conds ...gen.Condition) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Not(conds...))
}

func (d daemonGcTagRunnerDo) Or(conds ...gen.Condition) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Or(conds...))
}

func (d daemonGcTagRunnerDo) Select(conds ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Select(conds...))
}

func (d daemonGcTagRunnerDo) Where(conds ...gen.Condition) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Where(conds...))
}

func (d daemonGcTagRunnerDo) Order(conds ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Order(conds...))
}

func (d daemonGcTagRunnerDo) Distinct(cols ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Distinct(cols...))
}

func (d daemonGcTagRunnerDo) Omit(cols ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Omit(cols...))
}

func (d daemonGcTagRunnerDo) Join(table schema.Tabler, on ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Join(table, on...))
}

func (d daemonGcTagRunnerDo) LeftJoin(table schema.Tabler, on ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.LeftJoin(table, on...))
}

func (d daemonGcTagRunnerDo) RightJoin(table schema.Tabler, on ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.RightJoin(table, on...))
}

func (d daemonGcTagRunnerDo) Group(cols ...field.Expr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Group(cols...))
}

func (d daemonGcTagRunnerDo) Having(conds ...gen.Condition) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Having(conds...))
}

func (d daemonGcTagRunnerDo) Limit(limit int) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Limit(limit))
}

func (d daemonGcTagRunnerDo) Offset(offset int) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Offset(offset))
}

func (d daemonGcTagRunnerDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Scopes(funcs...))
}

func (d daemonGcTagRunnerDo) Unscoped() *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Unscoped())
}

func (d daemonGcTagRunnerDo) Create(values ...*models.DaemonGcTagRunner) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Create(values)
}

func (d daemonGcTagRunnerDo) CreateInBatches(values []*models.DaemonGcTagRunner, batchSize int) error {
	return d.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (d daemonGcTagRunnerDo) Save(values ...*models.DaemonGcTagRunner) error {
	if len(values) == 0 {
		return nil
	}
	return d.DO.Save(values)
}

func (d daemonGcTagRunnerDo) First() (*models.DaemonGcTagRunner, error) {
	if result, err := d.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRunner), nil
	}
}

func (d daemonGcTagRunnerDo) Take() (*models.DaemonGcTagRunner, error) {
	if result, err := d.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRunner), nil
	}
}

func (d daemonGcTagRunnerDo) Last() (*models.DaemonGcTagRunner, error) {
	if result, err := d.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRunner), nil
	}
}

func (d daemonGcTagRunnerDo) Find() ([]*models.DaemonGcTagRunner, error) {
	result, err := d.DO.Find()
	return result.([]*models.DaemonGcTagRunner), err
}

func (d daemonGcTagRunnerDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.DaemonGcTagRunner, err error) {
	buf := make([]*models.DaemonGcTagRunner, 0, batchSize)
	err = d.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (d daemonGcTagRunnerDo) FindInBatches(result *[]*models.DaemonGcTagRunner, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return d.DO.FindInBatches(result, batchSize, fc)
}

func (d daemonGcTagRunnerDo) Attrs(attrs ...field.AssignExpr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Attrs(attrs...))
}

func (d daemonGcTagRunnerDo) Assign(attrs ...field.AssignExpr) *daemonGcTagRunnerDo {
	return d.withDO(d.DO.Assign(attrs...))
}

func (d daemonGcTagRunnerDo) Joins(fields ...field.RelationField) *daemonGcTagRunnerDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Joins(_f))
	}
	return &d
}

func (d daemonGcTagRunnerDo) Preload(fields ...field.RelationField) *daemonGcTagRunnerDo {
	for _, _f := range fields {
		d = *d.withDO(d.DO.Preload(_f))
	}
	return &d
}

func (d daemonGcTagRunnerDo) FirstOrInit() (*models.DaemonGcTagRunner, error) {
	if result, err := d.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRunner), nil
	}
}

func (d daemonGcTagRunnerDo) FirstOrCreate() (*models.DaemonGcTagRunner, error) {
	if result, err := d.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.DaemonGcTagRunner), nil
	}
}

func (d daemonGcTagRunnerDo) FindByPage(offset int, limit int) (result []*models.DaemonGcTagRunner, count int64, err error) {
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

func (d daemonGcTagRunnerDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = d.Count()
	if err != nil {
		return
	}

	err = d.Offset(offset).Limit(limit).Scan(result)
	return
}

func (d daemonGcTagRunnerDo) Scan(result interface{}) (err error) {
	return d.DO.Scan(result)
}

func (d daemonGcTagRunnerDo) Delete(models ...*models.DaemonGcTagRunner) (result gen.ResultInfo, err error) {
	return d.DO.Delete(models)
}

func (d *daemonGcTagRunnerDo) withDO(do gen.Dao) *daemonGcTagRunnerDo {
	d.DO = *do.(*gen.DO)
	return d
}
