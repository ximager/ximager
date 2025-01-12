package dao

import (
	"context"

	"github.com/go-sigma/sigma/pkg/dal/models"
	"github.com/go-sigma/sigma/pkg/dal/query"
	"github.com/go-sigma/sigma/pkg/types/enums"
)

//go:generate mockgen -destination=mocks/authrule.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao AuthRuleService
//go:generate mockgen -destination=mocks/authrule_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao AuthRuleServiceFactory

// AuthRuleService is the interface that provides methods to operate on auth rule model
type AuthRuleService interface {
	// Create creates a new auth rule record in the database
	Create(ctx context.Context, authRule *models.AuthRule) error
}

type authRuleService struct {
	tx *query.Query
}

// AuthRuleServiceFactory is the interface that provides the auth rule service factory methods
type AuthRuleServiceFactory interface {
	New(txs ...*query.Query) AuthRuleService
}

type authRuleServiceFactory struct{}

// NewAuthRuleServiceFactory creates a new auth rule service factory
func NewAuthRuleServiceFactory() AuthRuleServiceFactory {
	return &authRuleServiceFactory{}
}

// New creates a new auth rule service
func (s *authRuleServiceFactory) New(txs ...*query.Query) AuthRuleService {
	tx := query.Q
	if len(txs) > 0 {
		tx = txs[0]
	}
	return &authRuleService{
		tx: tx,
	}
}

// Create create a auth rule
func (s *authRuleService) Create(ctx context.Context, authRule *models.AuthRule) error {
	return s.tx.AuthRule.WithContext(ctx).Create(authRule)
}

// ListByResource list auth rule by resource
func (s *authRuleService) ListByResource(ctx context.Context, resource enums.AuthResource) ([]*models.AuthRule, error) {
	return s.tx.AuthRule.WithContext(ctx).Where(s.tx.AuthRule.Resource.Eq(resource)).Find()
}
