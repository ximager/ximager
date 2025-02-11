// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: WebhookService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/webhook.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao WebhookService
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	models "github.com/go-sigma/sigma/pkg/dal/models"
	types "github.com/go-sigma/sigma/pkg/types"
	gomock "go.uber.org/mock/gomock"
)

// MockWebhookService is a mock of WebhookService interface.
type MockWebhookService struct {
	ctrl     *gomock.Controller
	recorder *MockWebhookServiceMockRecorder
	isgomock struct{}
}

// MockWebhookServiceMockRecorder is the mock recorder for MockWebhookService.
type MockWebhookServiceMockRecorder struct {
	mock *MockWebhookService
}

// NewMockWebhookService creates a new mock instance.
func NewMockWebhookService(ctrl *gomock.Controller) *MockWebhookService {
	mock := &MockWebhookService{ctrl: ctrl}
	mock.recorder = &MockWebhookServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWebhookService) EXPECT() *MockWebhookServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockWebhookService) Create(ctx context.Context, webhook *models.Webhook) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, webhook)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockWebhookServiceMockRecorder) Create(ctx, webhook any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockWebhookService)(nil).Create), ctx, webhook)
}

// CreateLog mocks base method.
func (m *MockWebhookService) CreateLog(ctx context.Context, webhookLog *models.WebhookLog) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateLog", ctx, webhookLog)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateLog indicates an expected call of CreateLog.
func (mr *MockWebhookServiceMockRecorder) CreateLog(ctx, webhookLog any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateLog", reflect.TypeOf((*MockWebhookService)(nil).CreateLog), ctx, webhookLog)
}

// DeleteByID mocks base method.
func (m *MockWebhookService) DeleteByID(ctx context.Context, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockWebhookServiceMockRecorder) DeleteByID(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockWebhookService)(nil).DeleteByID), ctx, id)
}

// DeleteLogByID mocks base method.
func (m *MockWebhookService) DeleteLogByID(ctx context.Context, webhookLogID int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteLogByID", ctx, webhookLogID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteLogByID indicates an expected call of DeleteLogByID.
func (mr *MockWebhookServiceMockRecorder) DeleteLogByID(ctx, webhookLogID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteLogByID", reflect.TypeOf((*MockWebhookService)(nil).DeleteLogByID), ctx, webhookLogID)
}

// Get mocks base method.
func (m *MockWebhookService) Get(ctx context.Context, id int64) (*models.Webhook, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, id)
	ret0, _ := ret[0].(*models.Webhook)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockWebhookServiceMockRecorder) Get(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockWebhookService)(nil).Get), ctx, id)
}

// GetByFilter mocks base method.
func (m *MockWebhookService) GetByFilter(ctx context.Context, filter map[string]any) ([]*models.Webhook, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByFilter", ctx, filter)
	ret0, _ := ret[0].([]*models.Webhook)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByFilter indicates an expected call of GetByFilter.
func (mr *MockWebhookServiceMockRecorder) GetByFilter(ctx, filter any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByFilter", reflect.TypeOf((*MockWebhookService)(nil).GetByFilter), ctx, filter)
}

// GetLog mocks base method.
func (m *MockWebhookService) GetLog(ctx context.Context, webhookLogID int64) (*models.WebhookLog, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLog", ctx, webhookLogID)
	ret0, _ := ret[0].(*models.WebhookLog)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLog indicates an expected call of GetLog.
func (mr *MockWebhookServiceMockRecorder) GetLog(ctx, webhookLogID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLog", reflect.TypeOf((*MockWebhookService)(nil).GetLog), ctx, webhookLogID)
}

// List mocks base method.
func (m *MockWebhookService) List(ctx context.Context, namespaceID *int64, pagination types.Pagination, sort types.Sortable) ([]*models.Webhook, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, namespaceID, pagination, sort)
	ret0, _ := ret[0].([]*models.Webhook)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// List indicates an expected call of List.
func (mr *MockWebhookServiceMockRecorder) List(ctx, namespaceID, pagination, sort any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockWebhookService)(nil).List), ctx, namespaceID, pagination, sort)
}

// ListLogs mocks base method.
func (m *MockWebhookService) ListLogs(ctx context.Context, webhookID int64, pagination types.Pagination, sort types.Sortable) ([]*models.WebhookLog, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListLogs", ctx, webhookID, pagination, sort)
	ret0, _ := ret[0].([]*models.WebhookLog)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ListLogs indicates an expected call of ListLogs.
func (mr *MockWebhookServiceMockRecorder) ListLogs(ctx, webhookID, pagination, sort any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListLogs", reflect.TypeOf((*MockWebhookService)(nil).ListLogs), ctx, webhookID, pagination, sort)
}

// UpdateByID mocks base method.
func (m *MockWebhookService) UpdateByID(ctx context.Context, id int64, updates map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateByID", ctx, id, updates)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateByID indicates an expected call of UpdateByID.
func (mr *MockWebhookServiceMockRecorder) UpdateByID(ctx, id, updates any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateByID", reflect.TypeOf((*MockWebhookService)(nil).UpdateByID), ctx, id, updates)
}
