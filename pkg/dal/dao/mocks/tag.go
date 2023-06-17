// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ximager/ximager/pkg/dal/dao (interfaces: TagService)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/ximager/ximager/pkg/dal/models"
	types "github.com/ximager/ximager/pkg/types"
)

// MockTagService is a mock of TagService interface.
type MockTagService struct {
	ctrl     *gomock.Controller
	recorder *MockTagServiceMockRecorder
}

// MockTagServiceMockRecorder is the mock recorder for MockTagService.
type MockTagServiceMockRecorder struct {
	mock *MockTagService
}

// NewMockTagService creates a new mock instance.
func NewMockTagService(ctrl *gomock.Controller) *MockTagService {
	mock := &MockTagService{ctrl: ctrl}
	mock.recorder = &MockTagServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTagService) EXPECT() *MockTagServiceMockRecorder {
	return m.recorder
}

// CountByArtifact mocks base method.
func (m *MockTagService) CountByArtifact(arg0 context.Context, arg1 []uint64) (map[uint64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByArtifact", arg0, arg1)
	ret0, _ := ret[0].(map[uint64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByArtifact indicates an expected call of CountByArtifact.
func (mr *MockTagServiceMockRecorder) CountByArtifact(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByArtifact", reflect.TypeOf((*MockTagService)(nil).CountByArtifact), arg0, arg1)
}

// CountTag mocks base method.
func (m *MockTagService) CountTag(arg0 context.Context, arg1 types.ListTagRequest) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountTag", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountTag indicates an expected call of CountTag.
func (mr *MockTagServiceMockRecorder) CountTag(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountTag", reflect.TypeOf((*MockTagService)(nil).CountTag), arg0, arg1)
}

// DeleteByArtifactID mocks base method.
func (m *MockTagService) DeleteByArtifactID(arg0 context.Context, arg1 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByArtifactID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByArtifactID indicates an expected call of DeleteByArtifactID.
func (mr *MockTagServiceMockRecorder) DeleteByArtifactID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByArtifactID", reflect.TypeOf((*MockTagService)(nil).DeleteByArtifactID), arg0, arg1)
}

// DeleteByID mocks base method.
func (m *MockTagService) DeleteByID(arg0 context.Context, arg1 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockTagServiceMockRecorder) DeleteByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockTagService)(nil).DeleteByID), arg0, arg1)
}

// DeleteByName mocks base method.
func (m *MockTagService) DeleteByName(arg0 context.Context, arg1 uint64, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByName", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByName indicates an expected call of DeleteByName.
func (mr *MockTagServiceMockRecorder) DeleteByName(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByName", reflect.TypeOf((*MockTagService)(nil).DeleteByName), arg0, arg1, arg2)
}

// GetByID mocks base method.
func (m *MockTagService) GetByID(arg0 context.Context, arg1 uint64) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", arg0, arg1)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockTagServiceMockRecorder) GetByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockTagService)(nil).GetByID), arg0, arg1)
}

// GetByName mocks base method.
func (m *MockTagService) GetByName(arg0 context.Context, arg1 uint64, arg2 string) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByName", arg0, arg1, arg2)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByName indicates an expected call of GetByName.
func (mr *MockTagServiceMockRecorder) GetByName(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByName", reflect.TypeOf((*MockTagService)(nil).GetByName), arg0, arg1, arg2)
}

// Incr mocks base method.
func (m *MockTagService) Incr(arg0 context.Context, arg1 uint64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Incr", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Incr indicates an expected call of Incr.
func (mr *MockTagServiceMockRecorder) Incr(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Incr", reflect.TypeOf((*MockTagService)(nil).Incr), arg0, arg1)
}

// ListByDtPagination mocks base method.
func (m *MockTagService) ListByDtPagination(arg0 context.Context, arg1 string, arg2 int, arg3 ...uint64) ([]*models.Tag, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1, arg2}
	for _, a := range arg3 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListByDtPagination", varargs...)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByDtPagination indicates an expected call of ListByDtPagination.
func (mr *MockTagServiceMockRecorder) ListByDtPagination(arg0, arg1, arg2 interface{}, arg3 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1, arg2}, arg3...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByDtPagination", reflect.TypeOf((*MockTagService)(nil).ListByDtPagination), varargs...)
}

// ListTag mocks base method.
func (m *MockTagService) ListTag(arg0 context.Context, arg1 types.ListTagRequest) ([]*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTag", arg0, arg1)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTag indicates an expected call of ListTag.
func (mr *MockTagServiceMockRecorder) ListTag(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTag", reflect.TypeOf((*MockTagService)(nil).ListTag), arg0, arg1)
}

// Save mocks base method.
func (m *MockTagService) Save(arg0 context.Context, arg1 *models.Tag) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Save", arg0, arg1)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Save indicates an expected call of Save.
func (mr *MockTagServiceMockRecorder) Save(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Save", reflect.TypeOf((*MockTagService)(nil).Save), arg0, arg1)
}
