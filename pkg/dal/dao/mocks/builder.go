// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: BuilderService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/builder.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao BuilderService
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"
	time "time"

	models "github.com/go-sigma/sigma/pkg/dal/models"
	types "github.com/go-sigma/sigma/pkg/types"
	gomock "go.uber.org/mock/gomock"
)

// MockBuilderService is a mock of BuilderService interface.
type MockBuilderService struct {
	ctrl     *gomock.Controller
	recorder *MockBuilderServiceMockRecorder
	isgomock struct{}
}

// MockBuilderServiceMockRecorder is the mock recorder for MockBuilderService.
type MockBuilderServiceMockRecorder struct {
	mock *MockBuilderService
}

// NewMockBuilderService creates a new mock instance.
func NewMockBuilderService(ctrl *gomock.Controller) *MockBuilderService {
	mock := &MockBuilderService{ctrl: ctrl}
	mock.recorder = &MockBuilderServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBuilderService) EXPECT() *MockBuilderServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockBuilderService) Create(ctx context.Context, builder *models.Builder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, builder)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockBuilderServiceMockRecorder) Create(ctx, builder any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBuilderService)(nil).Create), ctx, builder)
}

// CreateRunner mocks base method.
func (m *MockBuilderService) CreateRunner(ctx context.Context, runner *models.BuilderRunner) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateRunner", ctx, runner)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateRunner indicates an expected call of CreateRunner.
func (mr *MockBuilderServiceMockRecorder) CreateRunner(ctx, runner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRunner", reflect.TypeOf((*MockBuilderService)(nil).CreateRunner), ctx, runner)
}

// Get mocks base method.
func (m *MockBuilderService) Get(ctx context.Context, repositoryID int64) (*models.Builder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, repositoryID)
	ret0, _ := ret[0].(*models.Builder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockBuilderServiceMockRecorder) Get(ctx, repositoryID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockBuilderService)(nil).Get), ctx, repositoryID)
}

// GetByNextTrigger mocks base method.
func (m *MockBuilderService) GetByNextTrigger(ctx context.Context, now time.Time, limit int) ([]*models.Builder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByNextTrigger", ctx, now, limit)
	ret0, _ := ret[0].([]*models.Builder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByNextTrigger indicates an expected call of GetByNextTrigger.
func (mr *MockBuilderServiceMockRecorder) GetByNextTrigger(ctx, now, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByNextTrigger", reflect.TypeOf((*MockBuilderService)(nil).GetByNextTrigger), ctx, now, limit)
}

// GetByRepositoryID mocks base method.
func (m *MockBuilderService) GetByRepositoryID(ctx context.Context, repositoryID int64) (*models.Builder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByRepositoryID", ctx, repositoryID)
	ret0, _ := ret[0].(*models.Builder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByRepositoryID indicates an expected call of GetByRepositoryID.
func (mr *MockBuilderServiceMockRecorder) GetByRepositoryID(ctx, repositoryID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByRepositoryID", reflect.TypeOf((*MockBuilderService)(nil).GetByRepositoryID), ctx, repositoryID)
}

// GetByRepositoryIDs mocks base method.
func (m *MockBuilderService) GetByRepositoryIDs(ctx context.Context, repositoryIDs []int64) (map[int64]*models.Builder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByRepositoryIDs", ctx, repositoryIDs)
	ret0, _ := ret[0].(map[int64]*models.Builder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByRepositoryIDs indicates an expected call of GetByRepositoryIDs.
func (mr *MockBuilderServiceMockRecorder) GetByRepositoryIDs(ctx, repositoryIDs any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByRepositoryIDs", reflect.TypeOf((*MockBuilderService)(nil).GetByRepositoryIDs), ctx, repositoryIDs)
}

// GetRunner mocks base method.
func (m *MockBuilderService) GetRunner(ctx context.Context, id int64) (*models.BuilderRunner, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRunner", ctx, id)
	ret0, _ := ret[0].(*models.BuilderRunner)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRunner indicates an expected call of GetRunner.
func (mr *MockBuilderServiceMockRecorder) GetRunner(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRunner", reflect.TypeOf((*MockBuilderService)(nil).GetRunner), ctx, id)
}

// ListRunners mocks base method.
func (m *MockBuilderService) ListRunners(ctx context.Context, id int64, pagination types.Pagination, sort types.Sortable) ([]*models.BuilderRunner, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRunners", ctx, id, pagination, sort)
	ret0, _ := ret[0].([]*models.BuilderRunner)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ListRunners indicates an expected call of ListRunners.
func (mr *MockBuilderServiceMockRecorder) ListRunners(ctx, id, pagination, sort any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRunners", reflect.TypeOf((*MockBuilderService)(nil).ListRunners), ctx, id, pagination, sort)
}

// Update mocks base method.
func (m *MockBuilderService) Update(ctx context.Context, id int64, updates map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, updates)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockBuilderServiceMockRecorder) Update(ctx, id, updates any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockBuilderService)(nil).Update), ctx, id, updates)
}

// UpdateNextTrigger mocks base method.
func (m *MockBuilderService) UpdateNextTrigger(ctx context.Context, id int64, next time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateNextTrigger", ctx, id, next)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateNextTrigger indicates an expected call of UpdateNextTrigger.
func (mr *MockBuilderServiceMockRecorder) UpdateNextTrigger(ctx, id, next any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateNextTrigger", reflect.TypeOf((*MockBuilderService)(nil).UpdateNextTrigger), ctx, id, next)
}

// UpdateRunner mocks base method.
func (m *MockBuilderService) UpdateRunner(ctx context.Context, builderID, runnerID int64, updates map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateRunner", ctx, builderID, runnerID, updates)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateRunner indicates an expected call of UpdateRunner.
func (mr *MockBuilderServiceMockRecorder) UpdateRunner(ctx, builderID, runnerID, updates any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateRunner", reflect.TypeOf((*MockBuilderService)(nil).UpdateRunner), ctx, builderID, runnerID, updates)
}
