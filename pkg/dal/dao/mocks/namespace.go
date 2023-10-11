// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: NamespaceService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/namespace.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao NamespaceService
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

// MockNamespaceService is a mock of NamespaceService interface.
type MockNamespaceService struct {
	ctrl     *gomock.Controller
	recorder *MockNamespaceServiceMockRecorder
}

// MockNamespaceServiceMockRecorder is the mock recorder for MockNamespaceService.
type MockNamespaceServiceMockRecorder struct {
	mock *MockNamespaceService
}

// NewMockNamespaceService creates a new mock instance.
func NewMockNamespaceService(ctrl *gomock.Controller) *MockNamespaceService {
	mock := &MockNamespaceService{ctrl: ctrl}
	mock.recorder = &MockNamespaceServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNamespaceService) EXPECT() *MockNamespaceServiceMockRecorder {
	return m.recorder
}

// CountNamespace mocks base method.
func (m *MockNamespaceService) CountNamespace(arg0 context.Context, arg1 *string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountNamespace", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountNamespace indicates an expected call of CountNamespace.
func (mr *MockNamespaceServiceMockRecorder) CountNamespace(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountNamespace", reflect.TypeOf((*MockNamespaceService)(nil).CountNamespace), arg0, arg1)
}

// Create mocks base method.
func (m *MockNamespaceService) Create(arg0 context.Context, arg1 *models.Namespace) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockNamespaceServiceMockRecorder) Create(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockNamespaceService)(nil).Create), arg0, arg1)
}

// DeleteByID mocks base method.
func (m *MockNamespaceService) DeleteByID(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockNamespaceServiceMockRecorder) DeleteByID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockNamespaceService)(nil).DeleteByID), arg0, arg1)
}

// FindAll mocks base method.
func (m *MockNamespaceService) FindAll(arg0 context.Context) ([]*models.Namespace, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindAll", arg0)
	ret0, _ := ret[0].([]*models.Namespace)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindAll indicates an expected call of FindAll.
func (mr *MockNamespaceServiceMockRecorder) FindAll(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindAll", reflect.TypeOf((*MockNamespaceService)(nil).FindAll), arg0)
}

// Get mocks base method.
func (m *MockNamespaceService) Get(arg0 context.Context, arg1 int64) (*models.Namespace, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*models.Namespace)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockNamespaceServiceMockRecorder) Get(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockNamespaceService)(nil).Get), arg0, arg1)
}

// GetByName mocks base method.
func (m *MockNamespaceService) GetByName(arg0 context.Context, arg1 string) (*models.Namespace, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByName", arg0, arg1)
	ret0, _ := ret[0].(*models.Namespace)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByName indicates an expected call of GetByName.
func (mr *MockNamespaceServiceMockRecorder) GetByName(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByName", reflect.TypeOf((*MockNamespaceService)(nil).GetByName), arg0, arg1)
}

// ListNamespace mocks base method.
func (m *MockNamespaceService) ListNamespace(arg0 context.Context, arg1 *string, arg2 types.Pagination, arg3 types.Sortable) ([]*models.Namespace, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListNamespace", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]*models.Namespace)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ListNamespace indicates an expected call of ListNamespace.
func (mr *MockNamespaceServiceMockRecorder) ListNamespace(arg0, arg1, arg2, arg3 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListNamespace", reflect.TypeOf((*MockNamespaceService)(nil).ListNamespace), arg0, arg1, arg2, arg3)
}

// UpdateByID mocks base method.
func (m *MockNamespaceService) UpdateByID(arg0 context.Context, arg1 int64, arg2 map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateByID", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateByID indicates an expected call of UpdateByID.
func (mr *MockNamespaceServiceMockRecorder) UpdateByID(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateByID", reflect.TypeOf((*MockNamespaceService)(nil).UpdateByID), arg0, arg1, arg2)
}

// UpdateQuota mocks base method.
func (m *MockNamespaceService) UpdateQuota(arg0 context.Context, arg1, arg2 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateQuota", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateQuota indicates an expected call of UpdateQuota.
func (mr *MockNamespaceServiceMockRecorder) UpdateQuota(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateQuota", reflect.TypeOf((*MockNamespaceService)(nil).UpdateQuota), arg0, arg1, arg2)
}
