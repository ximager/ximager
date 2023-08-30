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

func newCodeRepository(db *gorm.DB, opts ...gen.DOOption) codeRepository {
	_codeRepository := codeRepository{}

	_codeRepository.codeRepositoryDo.UseDB(db, opts...)
	_codeRepository.codeRepositoryDo.UseModel(&models.CodeRepository{})

	tableName := _codeRepository.codeRepositoryDo.TableName()
	_codeRepository.ALL = field.NewAsterisk(tableName)
	_codeRepository.CreatedAt = field.NewTime(tableName, "created_at")
	_codeRepository.UpdatedAt = field.NewTime(tableName, "updated_at")
	_codeRepository.DeletedAt = field.NewUint(tableName, "deleted_at")
	_codeRepository.ID = field.NewInt64(tableName, "id")
	_codeRepository.User3rdPartyID = field.NewInt64(tableName, "user_3rdparty_id")
	_codeRepository.RepositoryID = field.NewString(tableName, "repository_id")
	_codeRepository.OwnerID = field.NewString(tableName, "owner_id")
	_codeRepository.Owner = field.NewString(tableName, "owner")
	_codeRepository.IsOrg = field.NewBool(tableName, "is_org")
	_codeRepository.Name = field.NewString(tableName, "name")
	_codeRepository.SshUrl = field.NewString(tableName, "ssh_url")
	_codeRepository.CloneUrl = field.NewString(tableName, "clone_url")
	_codeRepository.OciRepoCount = field.NewInt64(tableName, "oci_repo_count")
	_codeRepository.Branches = codeRepositoryHasManyBranches{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("Branches", "models.CodeRepositoryBranch"),
	}

	_codeRepository.User3rdParty = codeRepositoryBelongsToUser3rdParty{
		db: db.Session(&gorm.Session{}),

		RelationField: field.NewRelation("User3rdParty", "models.User3rdParty"),
		User: struct {
			field.RelationField
		}{
			RelationField: field.NewRelation("User3rdParty.User", "models.User"),
		},
	}

	_codeRepository.fillFieldMap()

	return _codeRepository
}

type codeRepository struct {
	codeRepositoryDo codeRepositoryDo

	ALL            field.Asterisk
	CreatedAt      field.Time
	UpdatedAt      field.Time
	DeletedAt      field.Uint
	ID             field.Int64
	User3rdPartyID field.Int64
	RepositoryID   field.String
	OwnerID        field.String
	Owner          field.String
	IsOrg          field.Bool
	Name           field.String
	SshUrl         field.String
	CloneUrl       field.String
	OciRepoCount   field.Int64
	Branches       codeRepositoryHasManyBranches

	User3rdParty codeRepositoryBelongsToUser3rdParty

	fieldMap map[string]field.Expr
}

func (c codeRepository) Table(newTableName string) *codeRepository {
	c.codeRepositoryDo.UseTable(newTableName)
	return c.updateTableName(newTableName)
}

func (c codeRepository) As(alias string) *codeRepository {
	c.codeRepositoryDo.DO = *(c.codeRepositoryDo.As(alias).(*gen.DO))
	return c.updateTableName(alias)
}

func (c *codeRepository) updateTableName(table string) *codeRepository {
	c.ALL = field.NewAsterisk(table)
	c.CreatedAt = field.NewTime(table, "created_at")
	c.UpdatedAt = field.NewTime(table, "updated_at")
	c.DeletedAt = field.NewUint(table, "deleted_at")
	c.ID = field.NewInt64(table, "id")
	c.User3rdPartyID = field.NewInt64(table, "user_3rdparty_id")
	c.RepositoryID = field.NewString(table, "repository_id")
	c.OwnerID = field.NewString(table, "owner_id")
	c.Owner = field.NewString(table, "owner")
	c.IsOrg = field.NewBool(table, "is_org")
	c.Name = field.NewString(table, "name")
	c.SshUrl = field.NewString(table, "ssh_url")
	c.CloneUrl = field.NewString(table, "clone_url")
	c.OciRepoCount = field.NewInt64(table, "oci_repo_count")

	c.fillFieldMap()

	return c
}

func (c *codeRepository) WithContext(ctx context.Context) *codeRepositoryDo {
	return c.codeRepositoryDo.WithContext(ctx)
}

func (c codeRepository) TableName() string { return c.codeRepositoryDo.TableName() }

func (c codeRepository) Alias() string { return c.codeRepositoryDo.Alias() }

func (c codeRepository) Columns(cols ...field.Expr) gen.Columns {
	return c.codeRepositoryDo.Columns(cols...)
}

func (c *codeRepository) GetFieldByName(fieldName string) (field.OrderExpr, bool) {
	_f, ok := c.fieldMap[fieldName]
	if !ok || _f == nil {
		return nil, false
	}
	_oe, ok := _f.(field.OrderExpr)
	return _oe, ok
}

func (c *codeRepository) fillFieldMap() {
	c.fieldMap = make(map[string]field.Expr, 15)
	c.fieldMap["created_at"] = c.CreatedAt
	c.fieldMap["updated_at"] = c.UpdatedAt
	c.fieldMap["deleted_at"] = c.DeletedAt
	c.fieldMap["id"] = c.ID
	c.fieldMap["user_3rdparty_id"] = c.User3rdPartyID
	c.fieldMap["repository_id"] = c.RepositoryID
	c.fieldMap["owner_id"] = c.OwnerID
	c.fieldMap["owner"] = c.Owner
	c.fieldMap["is_org"] = c.IsOrg
	c.fieldMap["name"] = c.Name
	c.fieldMap["ssh_url"] = c.SshUrl
	c.fieldMap["clone_url"] = c.CloneUrl
	c.fieldMap["oci_repo_count"] = c.OciRepoCount

}

func (c codeRepository) clone(db *gorm.DB) codeRepository {
	c.codeRepositoryDo.ReplaceConnPool(db.Statement.ConnPool)
	return c
}

func (c codeRepository) replaceDB(db *gorm.DB) codeRepository {
	c.codeRepositoryDo.ReplaceDB(db)
	return c
}

type codeRepositoryHasManyBranches struct {
	db *gorm.DB

	field.RelationField
}

func (a codeRepositoryHasManyBranches) Where(conds ...field.Expr) *codeRepositoryHasManyBranches {
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

func (a codeRepositoryHasManyBranches) WithContext(ctx context.Context) *codeRepositoryHasManyBranches {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a codeRepositoryHasManyBranches) Session(session *gorm.Session) *codeRepositoryHasManyBranches {
	a.db = a.db.Session(session)
	return &a
}

func (a codeRepositoryHasManyBranches) Model(m *models.CodeRepository) *codeRepositoryHasManyBranchesTx {
	return &codeRepositoryHasManyBranchesTx{a.db.Model(m).Association(a.Name())}
}

type codeRepositoryHasManyBranchesTx struct{ tx *gorm.Association }

func (a codeRepositoryHasManyBranchesTx) Find() (result []*models.CodeRepositoryBranch, err error) {
	return result, a.tx.Find(&result)
}

func (a codeRepositoryHasManyBranchesTx) Append(values ...*models.CodeRepositoryBranch) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a codeRepositoryHasManyBranchesTx) Replace(values ...*models.CodeRepositoryBranch) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a codeRepositoryHasManyBranchesTx) Delete(values ...*models.CodeRepositoryBranch) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a codeRepositoryHasManyBranchesTx) Clear() error {
	return a.tx.Clear()
}

func (a codeRepositoryHasManyBranchesTx) Count() int64 {
	return a.tx.Count()
}

type codeRepositoryBelongsToUser3rdParty struct {
	db *gorm.DB

	field.RelationField

	User struct {
		field.RelationField
	}
}

func (a codeRepositoryBelongsToUser3rdParty) Where(conds ...field.Expr) *codeRepositoryBelongsToUser3rdParty {
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

func (a codeRepositoryBelongsToUser3rdParty) WithContext(ctx context.Context) *codeRepositoryBelongsToUser3rdParty {
	a.db = a.db.WithContext(ctx)
	return &a
}

func (a codeRepositoryBelongsToUser3rdParty) Session(session *gorm.Session) *codeRepositoryBelongsToUser3rdParty {
	a.db = a.db.Session(session)
	return &a
}

func (a codeRepositoryBelongsToUser3rdParty) Model(m *models.CodeRepository) *codeRepositoryBelongsToUser3rdPartyTx {
	return &codeRepositoryBelongsToUser3rdPartyTx{a.db.Model(m).Association(a.Name())}
}

type codeRepositoryBelongsToUser3rdPartyTx struct{ tx *gorm.Association }

func (a codeRepositoryBelongsToUser3rdPartyTx) Find() (result *models.User3rdParty, err error) {
	return result, a.tx.Find(&result)
}

func (a codeRepositoryBelongsToUser3rdPartyTx) Append(values ...*models.User3rdParty) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Append(targetValues...)
}

func (a codeRepositoryBelongsToUser3rdPartyTx) Replace(values ...*models.User3rdParty) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Replace(targetValues...)
}

func (a codeRepositoryBelongsToUser3rdPartyTx) Delete(values ...*models.User3rdParty) (err error) {
	targetValues := make([]interface{}, len(values))
	for i, v := range values {
		targetValues[i] = v
	}
	return a.tx.Delete(targetValues...)
}

func (a codeRepositoryBelongsToUser3rdPartyTx) Clear() error {
	return a.tx.Clear()
}

func (a codeRepositoryBelongsToUser3rdPartyTx) Count() int64 {
	return a.tx.Count()
}

type codeRepositoryDo struct{ gen.DO }

func (c codeRepositoryDo) Debug() *codeRepositoryDo {
	return c.withDO(c.DO.Debug())
}

func (c codeRepositoryDo) WithContext(ctx context.Context) *codeRepositoryDo {
	return c.withDO(c.DO.WithContext(ctx))
}

func (c codeRepositoryDo) ReadDB() *codeRepositoryDo {
	return c.Clauses(dbresolver.Read)
}

func (c codeRepositoryDo) WriteDB() *codeRepositoryDo {
	return c.Clauses(dbresolver.Write)
}

func (c codeRepositoryDo) Session(config *gorm.Session) *codeRepositoryDo {
	return c.withDO(c.DO.Session(config))
}

func (c codeRepositoryDo) Clauses(conds ...clause.Expression) *codeRepositoryDo {
	return c.withDO(c.DO.Clauses(conds...))
}

func (c codeRepositoryDo) Returning(value interface{}, columns ...string) *codeRepositoryDo {
	return c.withDO(c.DO.Returning(value, columns...))
}

func (c codeRepositoryDo) Not(conds ...gen.Condition) *codeRepositoryDo {
	return c.withDO(c.DO.Not(conds...))
}

func (c codeRepositoryDo) Or(conds ...gen.Condition) *codeRepositoryDo {
	return c.withDO(c.DO.Or(conds...))
}

func (c codeRepositoryDo) Select(conds ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Select(conds...))
}

func (c codeRepositoryDo) Where(conds ...gen.Condition) *codeRepositoryDo {
	return c.withDO(c.DO.Where(conds...))
}

func (c codeRepositoryDo) Order(conds ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Order(conds...))
}

func (c codeRepositoryDo) Distinct(cols ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Distinct(cols...))
}

func (c codeRepositoryDo) Omit(cols ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Omit(cols...))
}

func (c codeRepositoryDo) Join(table schema.Tabler, on ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Join(table, on...))
}

func (c codeRepositoryDo) LeftJoin(table schema.Tabler, on ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.LeftJoin(table, on...))
}

func (c codeRepositoryDo) RightJoin(table schema.Tabler, on ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.RightJoin(table, on...))
}

func (c codeRepositoryDo) Group(cols ...field.Expr) *codeRepositoryDo {
	return c.withDO(c.DO.Group(cols...))
}

func (c codeRepositoryDo) Having(conds ...gen.Condition) *codeRepositoryDo {
	return c.withDO(c.DO.Having(conds...))
}

func (c codeRepositoryDo) Limit(limit int) *codeRepositoryDo {
	return c.withDO(c.DO.Limit(limit))
}

func (c codeRepositoryDo) Offset(offset int) *codeRepositoryDo {
	return c.withDO(c.DO.Offset(offset))
}

func (c codeRepositoryDo) Scopes(funcs ...func(gen.Dao) gen.Dao) *codeRepositoryDo {
	return c.withDO(c.DO.Scopes(funcs...))
}

func (c codeRepositoryDo) Unscoped() *codeRepositoryDo {
	return c.withDO(c.DO.Unscoped())
}

func (c codeRepositoryDo) Create(values ...*models.CodeRepository) error {
	if len(values) == 0 {
		return nil
	}
	return c.DO.Create(values)
}

func (c codeRepositoryDo) CreateInBatches(values []*models.CodeRepository, batchSize int) error {
	return c.DO.CreateInBatches(values, batchSize)
}

// Save : !!! underlying implementation is different with GORM
// The method is equivalent to executing the statement: db.Clauses(clause.OnConflict{UpdateAll: true}).Create(values)
func (c codeRepositoryDo) Save(values ...*models.CodeRepository) error {
	if len(values) == 0 {
		return nil
	}
	return c.DO.Save(values)
}

func (c codeRepositoryDo) First() (*models.CodeRepository, error) {
	if result, err := c.DO.First(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepository), nil
	}
}

func (c codeRepositoryDo) Take() (*models.CodeRepository, error) {
	if result, err := c.DO.Take(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepository), nil
	}
}

func (c codeRepositoryDo) Last() (*models.CodeRepository, error) {
	if result, err := c.DO.Last(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepository), nil
	}
}

func (c codeRepositoryDo) Find() ([]*models.CodeRepository, error) {
	result, err := c.DO.Find()
	return result.([]*models.CodeRepository), err
}

func (c codeRepositoryDo) FindInBatch(batchSize int, fc func(tx gen.Dao, batch int) error) (results []*models.CodeRepository, err error) {
	buf := make([]*models.CodeRepository, 0, batchSize)
	err = c.DO.FindInBatches(&buf, batchSize, func(tx gen.Dao, batch int) error {
		defer func() { results = append(results, buf...) }()
		return fc(tx, batch)
	})
	return results, err
}

func (c codeRepositoryDo) FindInBatches(result *[]*models.CodeRepository, batchSize int, fc func(tx gen.Dao, batch int) error) error {
	return c.DO.FindInBatches(result, batchSize, fc)
}

func (c codeRepositoryDo) Attrs(attrs ...field.AssignExpr) *codeRepositoryDo {
	return c.withDO(c.DO.Attrs(attrs...))
}

func (c codeRepositoryDo) Assign(attrs ...field.AssignExpr) *codeRepositoryDo {
	return c.withDO(c.DO.Assign(attrs...))
}

func (c codeRepositoryDo) Joins(fields ...field.RelationField) *codeRepositoryDo {
	for _, _f := range fields {
		c = *c.withDO(c.DO.Joins(_f))
	}
	return &c
}

func (c codeRepositoryDo) Preload(fields ...field.RelationField) *codeRepositoryDo {
	for _, _f := range fields {
		c = *c.withDO(c.DO.Preload(_f))
	}
	return &c
}

func (c codeRepositoryDo) FirstOrInit() (*models.CodeRepository, error) {
	if result, err := c.DO.FirstOrInit(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepository), nil
	}
}

func (c codeRepositoryDo) FirstOrCreate() (*models.CodeRepository, error) {
	if result, err := c.DO.FirstOrCreate(); err != nil {
		return nil, err
	} else {
		return result.(*models.CodeRepository), nil
	}
}

func (c codeRepositoryDo) FindByPage(offset int, limit int) (result []*models.CodeRepository, count int64, err error) {
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

func (c codeRepositoryDo) ScanByPage(result interface{}, offset int, limit int) (count int64, err error) {
	count, err = c.Count()
	if err != nil {
		return
	}

	err = c.Offset(offset).Limit(limit).Scan(result)
	return
}

func (c codeRepositoryDo) Scan(result interface{}) (err error) {
	return c.DO.Scan(result)
}

func (c codeRepositoryDo) Delete(models ...*models.CodeRepository) (result gen.ResultInfo, err error) {
	return c.DO.Delete(models)
}

func (c *codeRepositoryDo) withDO(do gen.Dao) *codeRepositoryDo {
	c.DO = *do.(*gen.DO)
	return c
}
