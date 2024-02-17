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

func newWebhookLog(db *gorm.DB, opts ...gen.DOOption) webhookLog {
	_webhookLog := webhookLog{}

	_webhookLog.webhookLogDo.UseDB(db, opts...)
	_webhookLog.webhookLogDo.UseModel(&models.WebhookLog{})

	tableName := _webhookLog.webhookLogDo.TableName()
	_webhookLog.ALL = field.NewAsterisk(tableName)
	_webhookLog.CreatedAt = field.NewInt64(tableName, "created_at")
	_webhookLog.UpdatedAt = field.NewInt64(tableName, "updated_at")
	_webhookLog.DeletedAt = field.NewUint64(tableName, "deleted_at")
	_webhookLog.ID = field.NewInt64(tableName, "id")
	_webhookLog.WebhookID = field.NewInt64(tableName, "webhook_id")
	_webhookLog.ResourceType = field.NewField(tableName, "resource_type")
	_webhookLog.Action = field.NewField(tableName, "action")
	_webhookLog.StatusCode = field.NewInt(tableName, "status_code")
	_webhookLog.ReqHeader = field.NewBytes(tableName, "req_header")
	_webhookLog.ReqBody = field.NewBytes(tableName, "req_body")
	_webhookLog.RespHeader = field.NewBytes(tableName, "resp_header")
	_webhookLog.RespBody = field.NewBytes(tableName, "resp_body")
	_webhookLog.Webhook = webhookLogBelongsToWebhook{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Webhook", "models.Webhook"),
	}

	_webhookLog.fillFieldMap()

	return _webhookLog
}

type webhookLog struct {
	webhookLogDo webhookLogDo

	ALL          field.Asterisk
	CreatedAt    field.Int64
	UpdatedAt    field.Int64
	DeletedAt    field.Uint64
	ID           field.Int64
	WebhookID    field.Int64
	ResourceType field.Field
	Action       field.Field
	StatusCode   field.Int
	ReqHeader    field.Bytes
	ReqBody      field.Bytes
	RespHeader   field.Bytes
	RespBody     field.Bytes
	Webhook      webhookLogBelongsToWebhook

	fieldMap map[string]field.Expr
}

func (w webhookLog) Table(newTableName string) *webhookLog {
	w.webhookLogDo.UseTable(newTableName)
	return w.updateTableName(newTableName)
}

func (w webhookLog) As(alias string) *webhookLog {
	w.webhookLogDo.DO = *(w.webhookLogDo.As(alias).(*gen.DO))
	return w.updateTableName(alias)
}

func (w *webhookLog) updateTableName(table string) *webhookLog {
	w.ALL = field.NewAsterisk(table)
	w.CreatedAt = field.NewInt64(table, "created_at")
	w.UpdatedAt = field.NewInt64(table, "updated_at")
	w.DeletedAt = field.NewUint64(table, "deleted_at")
	w.ID = field.NewInt64(table, "id")
	w.WebhookID = field.NewInt64(table, "webhook_id")
	w.ResourceType = field.NewField(table, "resource_type")
	w.Action = field.NewField(table, "action")
	w.StatusCode = field.NewInt(table, "status_code")
	w.ReqHeader = field.NewBytes(table, "req_header")
	w.ReqBody = field.NewBytes(table, "req_body")
	w.RespHeader = field.NewBytes(table, "resp_header")
	w.RespBody = field.NewBytes(table, "resp_body")

	w.fillFieldMap()

	return w
}

func (w *webhookLog) WithContext(ctx context.Context) *webhookLogDo {
	return w.webhookLogDo.WithContext(ctx)
}

func (w webhookLog) TableName() string { return w.webhookLogDo.TableName() }

func (w webhookLog) Alias() string { return w.webhookLogDo.Alias() }

func (w webhookLog) Columns(cols ...field.Expr) gen.Columns { return w.webhookLogDo.Columns(cols...) }

func (w *webhookLog) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := w.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (w *webhookLog) fillFieldMap() {
	w.fieldMap = make(map[string]field.Expr, 13)
	w.fieldMap["created_at"] = w.CreatedAt
	w.fieldMap["updated_at"] = w.UpdatedAt
	w.fieldMap["deleted_at"] = w.DeletedAt
	w.fieldMap["id"] = w.ID
	w.fieldMap["webhook_id"] = w.WebhookID
	w.fieldMap["resource_type"] = w.ResourceType
	w.fieldMap["action"] = w.Action
	w.fieldMap["status_code"] = w.StatusCode
	w.fieldMap["req_header"] = w.ReqHeader
	w.fieldMap["req_body"] = w.ReqBody
	w.fieldMap["resp_header"] = w.RespHeader
	w.fieldMap["resp_body"] = w.RespBody

}

func (w webhookLog) clone(db *gorm.DB) webhookLog {
	w.webhookLogDo.ReplaceConnPool(db.Statement.ConnPool)
	return w
}

func (w webhookLog) replaceDB(db *gorm.DB) webhookLog {
	w.webhookLogDo.ReplaceDB(db)
	return w
}

type webhookLogBelongsToWebhook struct {
	db *gorm.DB

	field.RelationField
}

func (a webhookLogBelongsToWebhook) Where(conds ...field.Expr) *webhookLogBelongsToWebhook {
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

func (a webhookLogBelongsToWebhook) WithContext(ctx context.Context) *webhookLogBelongsToWebhook {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a webhookLogBelongsToWebhook) Session(session *gorm.Session) *webhookLogBelongsToWebhook {
	a.db = a.db.Session(session)
	return &a
}

func (a webhookLogBelongsToWebhook) Model(m *models.WebhookLog) *webhookLogBelongsToWebhookTx {
	return &webhookLogBelongsToWebhookTx{a.db.Model(m).Association(a.Name())}
}

type webhookLogBelongsToWebhookTx struct{ tx *gorm.Association }

func (a webhookLogBelongsToWebhookTx) Find() (result *models.Webhook, err error) {
	return result, a.tx.Find(&result)
}

func (a webhookLogBelongsToWebhookTx) Append(values ...*models.Webhook) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a webhookLogBelongsToWebhookTx) Replace(values ...*models.Webhook) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a webhookLogBelongsToWebhookTx) Delete(values ...*models.Webhook) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a webhookLogBelongsToWebhookTx) Clear() error {
	return a.tx.Clear()
}

func (a webhookLogBelongsToWebhookTx) Count() int64 {
	return a.tx.Count()
}

type webhookLogDo struct{ gen.DO }

func (w webhookLogDo) Debug() *webhookLogDo {
	return w.withDO(w.DO.Debug())
}

func (w webhookLogDo) WithContext(ctx context.Context) *webhookLogDo {
	return w.withDO(w.DO.WithContext(ctx))
}

func (w webhookLogDo) ReadDB() *webhookLogDo {
	return w.Clauses(dbresolver.Read)
}

func (w webhookLogDo) WriteDB() *webhookLogDo {
	return w.Clauses(dbresolver.Write)
}

func (w webhookLogDo) Session(config *gorm.Session) *webhookLogDo {
	return w.withDO(w.DO.Session(config))
}

func (w webhookLogDo) Clauses(conds ...clause.Expression) *webhookLogDo {
	return w.withDO(w.DO.Clauses(conds...))
}

func (w webhookLogDo) Returning(value interface{}, columns ...string) *webhookLogDo {
	return w.withDO(w.DO.Returning(value, columns...))
}

func (w webhookLogDo) Not(conds ...gen.Condition) *webhookLogDo {
	return w.withDO(w.DO.Not(conds...))
}

func (w webhookLogDo) Or(conds ...gen.Condition) *webhookLogDo {
	return w.withDO(w.DO.Or(conds...))
}

func (w webhookLogDo) Select(conds ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Select(conds...))
}

func (w webhookLogDo) Where(conds ...gen.Condition) *webhookLogDo {
	return w.withDO(w.DO.Where(conds...))
}

func (w webhookLogDo) Order(conds ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Order(conds...))
}

func (w webhookLogDo) Distinct(cols ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Distinct(cols...))
}

func (w webhookLogDo) Omit(cols ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Omit(cols...))
}

func (w webhookLogDo) Join(table schema.Tabler, on ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Join(table, on...))
}

func (w webhookLogDo) LeftJoin(table schema.Tabler, on ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.LeftJoin(table, on...))
}

func (w webhookLogDo) RightJoin(table schema.Tabler, on ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.RightJoin(table, on...))
}

func (w webhookLogDo) Group(cols ...field.Expr) *webhookLogDo {
	return w.withDO(w.DO.Group(cols...))
}

func (w webhookLogDo) Having(conds ...gen.Condition) *webhookLogDo {
	return w.withDO(w.DO.Having(conds...))
}

func (w webhookLogDo) Limit(limit int) *webhookLogDo {
	return w.withDO(w.DO.Limit(limit))
}

func (w webhookLogDo) Offset(offset int) *webhookLogDo {
	return w.withDO(w.DO.Offset(offset))
}

func (w webhookLogDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *webhookLogDo {
	return w.withDO(w.DO.Scopes(funcs...))
}

func (w webhookLogDo) Unscoped() *webhookLogDo {
	return w.withDO(w.DO.Unscoped())
}

func (w webhookLogDo) Create(values ...*models.WebhookLog) error {
	if len(values) == 0 {
		return nil
	}
	return w.DO.Create(values)
}

func (w webhookLogDo) CreateInBatches(values []*models.WebhookLog, batchSize int) error {
	return w.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (w webhookLogDo) Save(values ...*models.WebhookLog) error {
	if len(values) == 0 {
		return nil
	}
	return w.DO.Save(values)
}

func (w webhookLogDo) First() (*models.WebhookLog, error) {
	if result, err := w.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.WebhookLog), nil
	}
}

func (w webhookLogDo) Take() (*models.WebhookLog, error) {
	if result, err := w.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.WebhookLog), nil
	}
}

func (w webhookLogDo) Last() (*models.WebhookLog, error) {
	if result, err := w.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.WebhookLog), nil
	}
}

func (w webhookLogDo) Find() ([]*models.WebhookLog, error) {
	result, err := w.DO.Find()
	return result.([]*models.WebhookLog), err
}

func (w webhookLogDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.WebhookLog, err error) {
	buf := make([]*models.WebhookLog, 0, batchSize)
	err = w.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (w webhookLogDo) FindInBatches(result *[]*models.WebhookLog, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return w.DO.FindInBatches(result, batchSize, fc)
}

func (w webhookLogDo) Attrs(attrs ...field.AssignExpr) *webhookLogDo {
	return w.withDO(w.DO.Attrs(attrs...))
}

func (w webhookLogDo) Assign(attrs ...field.AssignExpr) *webhookLogDo {
	return w.withDO(w.DO.Assign(attrs...))
}

func (w webhookLogDo) Joins(fields ...field.RelationField) *webhookLogDo {
	for _, _f := range fields {
		w = *w.withDO(w.DO.Joins(_f))
	}
	return &w
}

func (w webhookLogDo) Preload(fields ...field.RelationField) *webhookLogDo {
	for _, _f := range fields {
		w = *w.withDO(w.DO.Preload(_f))
	}
	return &w
}

func (w webhookLogDo) FirstOrInit() (*models.WebhookLog, error) {
	if result, err := w.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.WebhookLog), nil
	}
}

func (w webhookLogDo) FirstOrCreate() (*models.WebhookLog, error) {
	if result, err := w.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.WebhookLog), nil
	}
}

func (w webhookLogDo) FindByPage(offset int, limit int) (result []*models.WebhookLog, count int64, err error) {
	result, err = w.Offset(offset).Limit(limit).Find()
	if err != nil {
		return
	}

	if size := len(result); 0 < limit && 0 < size && size < limit {
		count = int64(size + offset)
		return
	}

	count, err = w.Offset(-1).Limit(-1).Count()
	return
}

func (w webhookLogDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = w.Count()
	if err != nil {
		return
	}

	err = w.Offset(offset).Limit(limit).Scan(result)
	return
}

func (w webhookLogDo) Scan(result interface{}) (err error) {
	return w.DO.Scan(result)
}

func (w webhookLogDo) Delete(models ...*models.WebhookLog) (result gen.ResultInfo, err error) {
	return w.DO.Delete(models)
}

func (w *webhookLogDo) withDO(do gen.Dao) *webhookLogDo {
	w.DO = *do.(*gen.DO)
	return w
}
