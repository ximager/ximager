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

func newAuthRule(db *gorm.DB, opts ...gen.DOOption) authRule {
	_authRule := authRule{}

	_authRule.authRuleDo.UseDB(db, opts...)
	_authRule.authRuleDo.UseModel(&models.AuthRule{})

	tableName := _authRule.authRuleDo.TableName()
	_authRule.ALL = field.NewAsterisk(tableName)
	_authRule.CreatedAt = field.NewInt64(tableName, "created_at")
	_authRule.UpdatedAt = field.NewInt64(tableName, "updated_at")
	_authRule.DeletedAt = field.NewUint64(tableName, "deleted_at")
	_authRule.ID = field.NewString(tableName, "ulid,maxsize:26,primaryKey")
	_authRule.RoleID = field.NewString(tableName, "role_id")
	_authRule.ScopeValue = field.NewString(tableName, "scope_value")
	_authRule.ScopeType = field.NewField(tableName, "scope_type")
	_authRule.UserID = field.NewString(tableName, "user_id")
	_authRule.Role = authRuleBelongsToRole{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Role", "models.AuthRole"),
	}

	_authRule.User = authRuleBelongsToUser{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("User", "models.User"),
	}

	_authRule.fillFieldMap()

	return _authRule
}

type authRule struct {
	authRuleDo authRuleDo

	ALL        field.Asterisk
	CreatedAt  field.Int64
	UpdatedAt  field.Int64
	DeletedAt  field.Uint64
	ID         field.String
	RoleID     field.String
	ScopeValue field.String
	ScopeType  field.Field
	UserID     field.String
	Role       authRuleBelongsToRole

	User authRuleBelongsToUser

	fieldMap map[string]field.Expr
}

func (a authRule) Table(newTableName string) *authRule {
	a.authRuleDo.UseTable(newTableName)
	return a.updateTableName(newTableName)
}

func (a authRule) As(alias string) *authRule {
	a.authRuleDo.DO = *(a.authRuleDo.As(alias).(*gen.DO))
	return a.updateTableName(alias)
}

func (a *authRule) updateTableName(table string) *authRule {
	a.ALL = field.NewAsterisk(table)
	a.CreatedAt = field.NewInt64(table, "created_at")
	a.UpdatedAt = field.NewInt64(table, "updated_at")
	a.DeletedAt = field.NewUint64(table, "deleted_at")
	a.ID = field.NewString(table, "ulid,maxsize:26,primaryKey")
	a.RoleID = field.NewString(table, "role_id")
	a.ScopeValue = field.NewString(table, "scope_value")
	a.ScopeType = field.NewField(table, "scope_type")
	a.UserID = field.NewString(table, "user_id")

	a.fillFieldMap()

	return a
}

func (a *authRule) WithContext(ctx context.Context) *authRuleDo { return a.authRuleDo.WithContext(ctx) }

func (a authRule) TableName() string { return a.authRuleDo.TableName() }

func (a authRule) Alias() string { return a.authRuleDo.Alias() }

func (a authRule) Columns(cols ...field.Expr) gen.Columns { return a.authRuleDo.Columns(cols...) }

func (a *authRule) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := a.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (a *authRule) fillFieldMap() {
	a.fieldMap = make(map[string]field.Expr, 10)
	a.fieldMap["created_at"] = a.CreatedAt
	a.fieldMap["updated_at"] = a.UpdatedAt
	a.fieldMap["deleted_at"] = a.DeletedAt
	a.fieldMap["ulid,maxsize:26,primaryKey"] = a.ID
	a.fieldMap["role_id"] = a.RoleID
	a.fieldMap["scope_value"] = a.ScopeValue
	a.fieldMap["scope_type"] = a.ScopeType
	a.fieldMap["user_id"] = a.UserID

}

func (a authRule) clone(db *gorm.DB) authRule {
	a.authRuleDo.ReplaceConnPool(db.Statement.ConnPool)
	return a
}

func (a authRule) replaceDB(db *gorm.DB) authRule {
	a.authRuleDo.ReplaceDB(db)
	return a
}

type authRuleBelongsToRole struct {
	db *gorm.DB

	field.RelationField
}

func (a authRuleBelongsToRole) Where(conds ...field.Expr) *authRuleBelongsToRole {
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

func (a authRuleBelongsToRole) WithContext(ctx context.Context) *authRuleBelongsToRole {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a authRuleBelongsToRole) Session(session *gorm.Session) *authRuleBelongsToRole {
	a.db = a.db.Session(session)
	return &a
}

func (a authRuleBelongsToRole) Model(m *models.AuthRule) *authRuleBelongsToRoleTx {
	return &authRuleBelongsToRoleTx{a.db.Model(m).Association(a.Name())}
}

type authRuleBelongsToRoleTx struct{ tx *gorm.Association }

func (a authRuleBelongsToRoleTx) Find() (result *models.AuthRole, err error) {
	return result, a.tx.Find(&result)
}

func (a authRuleBelongsToRoleTx) Append(values ...*models.AuthRole) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a authRuleBelongsToRoleTx) Replace(values ...*models.AuthRole) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a authRuleBelongsToRoleTx) Delete(values ...*models.AuthRole) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a authRuleBelongsToRoleTx) Clear() error {
	return a.tx.Clear()
}

func (a authRuleBelongsToRoleTx) Count() int64 {
	return a.tx.Count()
}

type authRuleBelongsToUser struct {
	db *gorm.DB

	field.RelationField
}

func (a authRuleBelongsToUser) Where(conds ...field.Expr) *authRuleBelongsToUser {
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

func (a authRuleBelongsToUser) WithContext(ctx context.Context) *authRuleBelongsToUser {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a authRuleBelongsToUser) Session(session *gorm.Session) *authRuleBelongsToUser {
	a.db = a.db.Session(session)
	return &a
}

func (a authRuleBelongsToUser) Model(m *models.AuthRule) *authRuleBelongsToUserTx {
	return &authRuleBelongsToUserTx{a.db.Model(m).Association(a.Name())}
}

type authRuleBelongsToUserTx struct{ tx *gorm.Association }

func (a authRuleBelongsToUserTx) Find() (result *models.User, err error) {
	return result, a.tx.Find(&result)
}

func (a authRuleBelongsToUserTx) Append(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a authRuleBelongsToUserTx) Replace(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a authRuleBelongsToUserTx) Delete(values ...*models.User) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a authRuleBelongsToUserTx) Clear() error {
	return a.tx.Clear()
}

func (a authRuleBelongsToUserTx) Count() int64 {
	return a.tx.Count()
}

type authRuleDo struct{ gen.DO }

func (a authRuleDo) Debug() *authRuleDo {
	return a.withDO(a.DO.Debug())
}

func (a authRuleDo) WithContext(ctx context.Context) *authRuleDo {
	return a.withDO(a.DO.WithContext(ctx))
}

func (a authRuleDo) ReadDB() *authRuleDo {
	return a.Clauses(dbresolver.Read)
}

func (a authRuleDo) WriteDB() *authRuleDo {
	return a.Clauses(dbresolver.Write)
}

func (a authRuleDo) Session(config *gorm.Session) *authRuleDo {
	return a.withDO(a.DO.Session(config))
}

func (a authRuleDo) Clauses(conds ...clause.Expression) *authRuleDo {
	return a.withDO(a.DO.Clauses(conds...))
}

func (a authRuleDo) Returning(value interface{}, columns ...string) *authRuleDo {
	return a.withDO(a.DO.Returning(value, columns...))
}

func (a authRuleDo) Not(conds ...gen.Condition) *authRuleDo {
	return a.withDO(a.DO.Not(conds...))
}

func (a authRuleDo) Or(conds ...gen.Condition) *authRuleDo {
	return a.withDO(a.DO.Or(conds...))
}

func (a authRuleDo) Select(conds ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Select(conds...))
}

func (a authRuleDo) Where(conds ...gen.Condition) *authRuleDo {
	return a.withDO(a.DO.Where(conds...))
}

func (a authRuleDo) Order(conds ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Order(conds...))
}

func (a authRuleDo) Distinct(cols ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Distinct(cols...))
}

func (a authRuleDo) Omit(cols ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Omit(cols...))
}

func (a authRuleDo) Join(table schema.Tabler, on ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Join(table, on...))
}

func (a authRuleDo) LeftJoin(table schema.Tabler, on ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.LeftJoin(table, on...))
}

func (a authRuleDo) RightJoin(table schema.Tabler, on ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.RightJoin(table, on...))
}

func (a authRuleDo) Group(cols ...field.Expr) *authRuleDo {
	return a.withDO(a.DO.Group(cols...))
}

func (a authRuleDo) Having(conds ...gen.Condition) *authRuleDo {
	return a.withDO(a.DO.Having(conds...))
}

func (a authRuleDo) Limit(limit int) *authRuleDo {
	return a.withDO(a.DO.Limit(limit))
}

func (a authRuleDo) Offset(offset int) *authRuleDo {
	return a.withDO(a.DO.Offset(offset))
}

func (a authRuleDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *authRuleDo {
	return a.withDO(a.DO.Scopes(funcs...))
}

func (a authRuleDo) Unscoped() *authRuleDo {
	return a.withDO(a.DO.Unscoped())
}

func (a authRuleDo) Create(values ...*models.AuthRule) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Create(values)
}

func (a authRuleDo) CreateInBatches(values []*models.AuthRule, batchSize int) error {
	return a.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (a authRuleDo) Save(values ...*models.AuthRule) error {
	if len(values) == 0 {
		return nil
	}
	return a.DO.Save(values)
}

func (a authRuleDo) First() (*models.AuthRule, error) {
	if result, err := a.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.AuthRule), nil
	}
}

func (a authRuleDo) Take() (*models.AuthRule, error) {
	if result, err := a.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.AuthRule), nil
	}
}

func (a authRuleDo) Last() (*models.AuthRule, error) {
	if result, err := a.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.AuthRule), nil
	}
}

func (a authRuleDo) Find() ([]*models.AuthRule, error) {
	result, err := a.DO.Find()
	return result.([]*models.AuthRule), err
}

func (a authRuleDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.AuthRule, err error) {
	buf := make([]*models.AuthRule, 0, batchSize)
	err = a.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (a authRuleDo) FindInBatches(result *[]*models.AuthRule, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return a.DO.FindInBatches(result, batchSize, fc)
}

func (a authRuleDo) Attrs(attrs ...field.AssignExpr) *authRuleDo {
	return a.withDO(a.DO.Attrs(attrs...))
}

func (a authRuleDo) Assign(attrs ...field.AssignExpr) *authRuleDo {
	return a.withDO(a.DO.Assign(attrs...))
}

func (a authRuleDo) Joins(fields ...field.RelationField) *authRuleDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Joins(_f))
	}
	return &a
}

func (a authRuleDo) Preload(fields ...field.RelationField) *authRuleDo {
	for _, _f := range fields {
		a = *a.withDO(a.DO.Preload(_f))
	}
	return &a
}

func (a authRuleDo) FirstOrInit() (*models.AuthRule, error) {
	if result, err := a.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.AuthRule), nil
	}
}

func (a authRuleDo) FirstOrCreate() (*models.AuthRule, error) {
	if result, err := a.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.AuthRule), nil
	}
}

func (a authRuleDo) FindByPage(offset int, limit int) (result []*models.AuthRule, count int64, err error) {
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

func (a authRuleDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = a.Count()
	if err != nil {
		return
	}

	err = a.Offset(offset).Limit(limit).Scan(result)
	return
}

func (a authRuleDo) Scan(result interface{}) (err error) {
	return a.DO.Scan(result)
}

func (a authRuleDo) Delete(models ...*models.AuthRule) (result gen.ResultInfo, err error) {
	return a.DO.Delete(models)
}

func (a *authRuleDo) withDO(do gen.Dao) *authRuleDo {
	a.DO = *do.(*gen.DO)
	return a
}
