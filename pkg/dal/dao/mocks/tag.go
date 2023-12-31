// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: TagService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/tag.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao TagService
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	models "github.com/go-sigma/sigma/pkg/dal/models"
	types "github.com/go-sigma/sigma/pkg/types"
	enums "github.com/go-sigma/sigma/pkg/types/enums"
	gomock "go.uber.org/mock/gomock"
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
func (m *MockTagService) CountByArtifact(arg0 context.Context, arg1 []int64) (map[int64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByArtifact", arg0, arg1)
	ret0, _ := ret[0].(map[int64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByArtifact indicates an expected call of CountByArtifact.
func (mr *MockTagServiceMockRecorder) CountByArtifact(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByArtifact", reflect.TypeOf((*MockTagService)(nil).CountByArtifact), arg0, arg1)
}

// CountByNamespace mocks base method.
func (m *MockTagService) CountByNamespace(arg0 context.Context, arg1 []int64) (map[int64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByNamespace", arg0, arg1)
	ret0, _ := ret[0].(map[int64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByNamespace indicates an expected call of CountByNamespace.
func (mr *MockTagServiceMockRecorder) CountByNamespace(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByNamespace", reflect.TypeOf((*MockTagService)(nil).CountByNamespace), arg0, arg1)
}

// CountByRepositories mocks base method.
func (m *MockTagService) CountByRepositories(arg0 context.Context, arg1 []int64) (map[int64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByRepositories", arg0, arg1)
	ret0, _ := ret[0].(map[int64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByRepositories indicates an expected call of CountByRepositories.
func (mr *MockTagServiceMockRecorder) CountByRepositories(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByRepositories", reflect.TypeOf((*MockTagService)(nil).CountByRepositories), arg0, arg1)
}

// CountByRepository mocks base method.
func (m *MockTagService) CountByRepository(arg0 context.Context, arg1 int64) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByRepository", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByRepository indicates an expected call of CountByRepository.
func (mr *MockTagServiceMockRecorder) CountByRepository(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByRepository", reflect.TypeOf((*MockTagService)(nil).CountByRepository), arg0, arg1)
}

// Create mocks base method.
func (m *MockTagService) Create(arg0 context.Context, arg1 *models.Tag, arg2 ...dao.Option) error {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Create", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockTagServiceMockRecorder) Create(arg0, arg1 any, arg2 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockTagService)(nil).Create), varargs...)
}

// DeleteByArtifactID mocks base method.
func (m *MockTagService) DeleteByArtifactID(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByArtifactID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByArtifactID indicates an expected call of DeleteByArtifactID.
func (mr *MockTagServiceMockRecorder) DeleteByArtifactID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByArtifactID", reflect.TypeOf((*MockTagService)(nil).DeleteByArtifactID), arg0, arg1)
}

// DeleteByID mocks base method.
func (m *MockTagService) DeleteByID(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockTagServiceMockRecorder) DeleteByID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockTagService)(nil).DeleteByID), arg0, arg1)
}

// DeleteByName mocks base method.
func (m *MockTagService) DeleteByName(arg0 context.Context, arg1 int64, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByName", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByName indicates an expected call of DeleteByName.
func (mr *MockTagServiceMockRecorder) DeleteByName(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByName", reflect.TypeOf((*MockTagService)(nil).DeleteByName), arg0, arg1, arg2)
}

// FindWithDayCursor mocks base method.
func (m *MockTagService) FindWithDayCursor(arg0 context.Context, arg1 int64, arg2, arg3 int, arg4 int64) ([]*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindWithDayCursor", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindWithDayCursor indicates an expected call of FindWithDayCursor.
func (mr *MockTagServiceMockRecorder) FindWithDayCursor(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindWithDayCursor", reflect.TypeOf((*MockTagService)(nil).FindWithDayCursor), arg0, arg1, arg2, arg3, arg4)
}

// FindWithQuantityCursor mocks base method.
func (m *MockTagService) FindWithQuantityCursor(arg0 context.Context, arg1 int64, arg2, arg3 int, arg4 int64) ([]*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindWithQuantityCursor", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindWithQuantityCursor indicates an expected call of FindWithQuantityCursor.
func (mr *MockTagServiceMockRecorder) FindWithQuantityCursor(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindWithQuantityCursor", reflect.TypeOf((*MockTagService)(nil).FindWithQuantityCursor), arg0, arg1, arg2, arg3, arg4)
}

// GetByArtifactID mocks base method.
func (m *MockTagService) GetByArtifactID(arg0 context.Context, arg1, arg2 int64) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByArtifactID", arg0, arg1, arg2)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByArtifactID indicates an expected call of GetByArtifactID.
func (mr *MockTagServiceMockRecorder) GetByArtifactID(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByArtifactID", reflect.TypeOf((*MockTagService)(nil).GetByArtifactID), arg0, arg1, arg2)
}

// GetByID mocks base method.
func (m *MockTagService) GetByID(arg0 context.Context, arg1 int64) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByID", arg0, arg1)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByID indicates an expected call of GetByID.
func (mr *MockTagServiceMockRecorder) GetByID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByID", reflect.TypeOf((*MockTagService)(nil).GetByID), arg0, arg1)
}

// GetByName mocks base method.
func (m *MockTagService) GetByName(arg0 context.Context, arg1 int64, arg2 string) (*models.Tag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByName", arg0, arg1, arg2)
	ret0, _ := ret[0].(*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByName indicates an expected call of GetByName.
func (mr *MockTagServiceMockRecorder) GetByName(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByName", reflect.TypeOf((*MockTagService)(nil).GetByName), arg0, arg1, arg2)
}

// Incr mocks base method.
func (m *MockTagService) Incr(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Incr", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Incr indicates an expected call of Incr.
func (mr *MockTagServiceMockRecorder) Incr(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Incr", reflect.TypeOf((*MockTagService)(nil).Incr), arg0, arg1)
}

// ListByDtPagination mocks base method.
func (m *MockTagService) ListByDtPagination(arg0 context.Context, arg1 string, arg2 int, arg3 ...int64) ([]*models.Tag, error) {
	m.ctrl.T.Helper()
	varargs := []any{arg0, arg1, arg2}
	for _, a := range arg3 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListByDtPagination", varargs...)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListByDtPagination indicates an expected call of ListByDtPagination.
func (mr *MockTagServiceMockRecorder) ListByDtPagination(arg0, arg1, arg2 any, arg3 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{arg0, arg1, arg2}, arg3...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListByDtPagination", reflect.TypeOf((*MockTagService)(nil).ListByDtPagination), varargs...)
}

// ListTag mocks base method.
func (m *MockTagService) ListTag(arg0 context.Context, arg1 int64, arg2 *string, arg3 []enums.ArtifactType, arg4 types.Pagination, arg5 types.Sortable) ([]*models.Tag, int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTag", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].([]*models.Tag)
	ret1, _ := ret[1].(int64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ListTag indicates an expected call of ListTag.
func (mr *MockTagServiceMockRecorder) ListTag(arg0, arg1, arg2, arg3, arg4, arg5 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTag", reflect.TypeOf((*MockTagService)(nil).ListTag), arg0, arg1, arg2, arg3, arg4, arg5)
}
