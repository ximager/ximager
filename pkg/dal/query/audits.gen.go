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

func newAudit(db *gorm.DB, opts ...gen.DOOption) audit {
	_audit := audit{}

	_audit.auditDo.UseDB(db, opts...)
	_audit.auditDo.UseModel(&models.Audit{})

	tableName := _audit.auditDo.TableName()
	_audit.ALL = field.NewAsterisk(tableName)
	_audit.CreatedAt = field.NewInt64(tableName, "created_at")
	_audit.UpdatedAt = field.NewInt64(tableName, "updated_at")
	_audit.DeletedAt = field.NewUint64(tableName, "deleted_at")
	_audit.ID = field.NewInt64(tableName, "id")
	_audit.UserID = field.NewInt64(tableName, "user_id")
	_audit.NamespaceID = field.NewInt64(tableName, "namespace_id")
	_audit.Action = field.NewField(tableName, "action")
	_audit.ResourceType = field.NewField(tableName, "resource_type")
	_audit.Resource = field.NewString(tableName, "resource")
	_audit.ReqRaw = field.NewBytes(tableName, "req_raw")
	_audit.Namespace = auditBelongsToNamespace{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Namespace", "models.Namespace"),
	}

	_audit.User = auditBelongsToUser{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("User", "models.User"),
	}

	_audit.fillFieldMap()

	return _audit
}

type audit struct {
	auditDo auditDo

	ALL          field.Asterisk
	CreatedAt    field.Int64
	UpdatedAt    field.Int64
	DeletedAt    field.Uint64
	ID           field.Int64
	UserID       field.Int64
	NamespaceID  field.Int64
	Action       field.Field
	ResourceType field.Field
	Resource     field.String
	ReqRaw       field.Bytes
	Namespace    auditBelongsToNamespace

	User auditBelongsToUser

	fieldMap map[string]field.Expr
}

func (a audit) Table(newTableName string) *audit {
	a.auditDo.UseTable(newTableName)
	return a.updateTableName(newTableName)
}

func (a audit) As(alias string) *audit {
	a.auditDo.DO = *(a.auditDo.As(alias).(*gen.DO))
	return a.updateTableName(alias)
}

func (a *audit) updateTableName(table string) *audit {
	a.ALL = field.NewAsterisk(table)
	a.CreatedAt = field.NewInt64(table, "created_at")
	a.UpdatedAt = field.NewInt64(table, "updated_at")
	a.DeletedAt = field.NewUint64(table, "deleted_at")
	a.ID = field.NewInt64(table, "id")
	a.UserID = field.NewInt64(table, "user_id")
	a.NamespaceID = field.NewInt64(table, "namespace_id")
	a.Action = field.NewField(table, "action")
	a.ResourceType = field.NewField(table, "resource_type")
	a.Resource = field.NewString(table, "resource")
	a.ReqRaw = field.NewBytes(table, "req_raw")

	a.fillFieldMap()

	return a
}

func (a *audit) WithContext(ctx context.Context) *auditDo { return a.auditDo.WithContext(ctx) }

func (a audit) TableName() string { return a.auditDo.TableName() }

func (a audit) Alias() string { return a.auditDo.Alias() }

func (a audit) Columns(cols ...field.Expr) gen.Columns { return a.auditDo.Columns(cols...) }

func (a *audit) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := a.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (a *audit) fillFieldMap() {
	a.fieldMap = make(map[string]field.Expr, 12)
	a.fieldMap["created_at"] = a.CreatedAt
	a.fieldMap["updated_at"] = a.UpdatedAt
	a.fieldMap["deleted_at"] = a.DeletedAt
	a.fieldMap["id"] = a.ID
	a.fieldMap["user_id"] = a.UserID
	a.fieldMap["namespace_id"] = a.NamespaceID
	a.fieldMap["action"] = a.Action
	a.fieldMap["resource_type"] = a.ResourceType
	a.fieldMap["resource"] = a.Resource
	a.fieldMap["req_raw"] = a.ReqRaw

}

func (a audit) clone(db *gorm.DB) audit {
	a.auditDo.ReplaceConnPool(db.Statement.ConnPool)
	return a
}

func (a audit) replaceDB(db *gorm.DB) audit {
	a.auditDo.ReplaceDB(db)
	return a
}

type auditBelongsToNamespace struct {
	db *gorm.DB

	field.RelationField
}

func (a auditBelongsToNamespace) Where(conds ...field.Expr) *auditBelongsToNamespace {
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

func (a auditBelongsToNamespace) WithContext(ctx context.Context) *auditBelongsToNamespace {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a auditBelongsToNamespace) Session(session *gorm.Session) *auditBelongsToNamespace {
	a.db = a.db.Session(session)
	return &a
}

func (a auditBelongsToNamespace) Model(m *models.Audit) *auditBelongsToNamespaceTx {
	return &auditBelongsToNamespaceTx{a.db.Model(m).Association(a.Name())}
}

type auditBelongsToNamespaceTx struct{ tx *gorm.Association }

func (a auditBelongsToNamespaceTx) Find() (result *models.Namespace, err error) {
	return result, a.tx.Find(&result)
}

func (a auditBelongsToNamespaceTx) Append(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a auditBelongsToNamespaceTx) Replace(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a auditBelongsToNamespaceTx) Delete(values ...*models.Namespace) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a auditBelongsToNamespaceTx) Clear() error {
	return a.tx.Clear()
}

func (a auditBelongsToNamespaceTx) Count() int64 {
	return a.tx.Count()
}

type auditBelongsToUser struct {
	db *gorm.DB

	field.RelationField
}

func (a auditBelongsToUser) Where(conds ...field.Expr) *auditBelongsToUser {
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

func (a auditBelongsToUser) WithContext(ctx context.Context) *auditBelongsToUser {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a auditBelongsToUser) Session(session *gorm.Session) *auditBelongsToUser {
	a.db = a.db.Session(session)
	return &a
}

func (a auditBelongsToUser) Model(m *models.Audit) *auditBelongsToUserTx {
	return &auditBelongsToUserTx{a.db.Model(m).Association(a.Name())}
}

type auditBelongsToUserTx struct{ tx *gorm.Association }

func (a auditBelongsToUserTx) Find() (result *models.User, err error) {
	return result, a.tx.Find(&result)
}

func (a auditBelongsToUserTx) Append(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a auditBelongsToUserTx) Replace(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a auditBelongsToUserTx) Delete(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a auditBelongsToUserTx) Clear() error {
	return a.tx.Clear()
}

func (a auditBelongsToUserTx) Count() int64 {
	return a.tx.Count()
}

type auditDo struct{ gen.DO }

func (a auditDo) Debug() *auditDo {
	return a.withDO(a.DO.Debug())
}

func (a auditDo) WithContext(ctx context.Context) *auditDo {
	return a.withDO(a.DO.WithContext(ctx))
}

func (a auditDo) ReadDB() *auditDo {
	return a.Clauses(dbresolver.Read)
}

func (a auditDo) WriteDB() *auditDo {
	return a.Clauses(dbresolver.Write)
}

func (a auditDo) Session(config *gorm.Session) *auditDo {
	return a.withDO(a.DO.Session(config))
}

func (a auditDo) Clauses(conds ...clause.Expression) *auditDo {
	return a.withDO(a.DO.Clauses(conds...))
}

func (a auditDo) Returning(value interface{}, columns ...string) *auditDo {
	return a.withDO(a.DO.Returning(value, columns...))
}

func (a auditDo) Not(conds ...gen.Condition) *auditDo {
	return a.withDO(a.DO.Not(conds...))
}

func (a auditDo) Or(conds ...gen.Condition) *auditDo {
	return a.withDO(a.DO.Or(conds...))
}

func (a auditDo) Select(conds ...field.Expr) *auditDo {
	return a.withDO(a.DO.Select(conds...))
}

func (a auditDo) Where(conds ...gen.Condition) *auditDo {
	return a.withDO(a.DO.Where(conds...))
}

func (a auditDo) Order(conds ...field.Expr) *auditDo {
	return a.withDO(a.DO.Order(conds...))
}

func (a auditDo) Distinct(cols ...field.Expr) *auditDo {
	return a.withDO(a.DO.Distinct(cols...))
}

func (a auditDo) Omit(cols ...field.Expr) *auditDo {
	return a.withDO(a.DO.Omit(cols...))
}

func (a auditDo) Join(table schema.Tabler, on ...field.Expr) *auditDo {
	return a.withDO(a.DO.Join(table, on...))
}

func (a auditDo) LeftJoin(table schema.Tabler, on ...field.Expr) *auditDo {
	return a.withDO(a.DO.LeftJoin(table, on...))
}

func (a auditDo) RightJoin(table schema.Tabler, on ...field.Expr) *auditDo {
	return a.withDO(a.DO.RightJoin(table, on...))
}

func (a auditDo) Group(cols ...field.Expr) *auditDo {
	return a.withDO(a.DO.Group(cols...))
}

func (a auditDo) Having(conds ...gen.Condition) *auditDo {
	return a.withDO(a.DO.Having(conds...))
}

func (a auditDo) Limit(limit int) *auditDo {
	return a.withDO(a.DO.Limit(limit))
}

func (a auditDo) Offset(offset int) *auditDo {
	return a.withDO(a.DO.Offset(offset))
}

func (a auditDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *auditDo {
	return a.withDO(a.DO.Scopes(funcs...))
}

func (a auditDo) Unscoped() *auditDo {
	return a.withDO(a.DO.Unscoped())
}

func (a auditDo) Create(values ...*models.Audit) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Create(values)
}

func (a auditDo) CreateInBatches(values []*models.Audit, batchSize int) error {
	return a.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (a auditDo) Save(values ...*models.Audit) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Save(values)
}

func (a auditDo) First() (*models.Audit, error) {
	if result, err := a.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.Audit), nil
	}
}

func (a auditDo) Take() (*models.Audit, error) {
	if result, err := a.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.Audit), nil
	}
}

func (a auditDo) Last() (*models.Audit, error) {
	if result, err := a.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.Audit), nil
	}
}

func (a auditDo) Find() ([]*models.Audit, error) {
	result, err := a.DO.Find()
	return result.([]*models.Audit), err
}

func (a auditDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.Audit, err error) {
	buf := make([]*models.Audit, 0, batchSize)
	err = a.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (a auditDo) FindInBatches(result *[]*models.Audit, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return a.DO.FindInBatches(result, batchSize, fc)
}

func (a auditDo) Attrs(attrs ...field.AssignExpr) *auditDo {
	return a.withDO(a.DO.Attrs(attrs...))
}

func (a auditDo) Assign(attrs ...field.AssignExpr) *auditDo {
	return a.withDO(a.DO.Assign(attrs...))
}

func (a auditDo) Joins(fields ...field.RelationField) *auditDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Joins(_f))
	}
	return &a
}

func (a auditDo) Preload(fields ...field.RelationField) *auditDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Preload(_f))
	}
	return &a
}

func (a auditDo) FirstOrInit() (*models.Audit, error) {
	if result, err := a.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.Audit), nil
	}
}

func (a auditDo) FirstOrCreate() (*models.Audit, error) {
	if result, err := a.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.Audit), nil
	}
}

func (a auditDo) FindByPage(offset int, limit int) (result []*models.Audit, count int64, err error) {
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

func (a auditDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = a.Count()
	if err != nil {
		return
	}

	err = a.Offset(offset).Limit(limit).Scan(result)
	return
}

func (a auditDo) Scan(result interface{}) (err error) {
	return a.DO.Scan(result)
}

func (a auditDo) Delete(models ...*models.Audit) (result gen.ResultInfo, err error) {
	return a.DO.Delete(models)
}

func (a *auditDo) withDO(do gen.Dao) *auditDo {
	a.DO = *do.(*gen.DO)
	return a
}
