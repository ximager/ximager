// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ximager/ximager/pkg/dal/dao (interfaces: BlobService)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/ximager/ximager/pkg/dal/models"
)

// MockBlobService is a mock of BlobService interface.
type MockBlobService struct {
	ctrl     *gomock.Controller
	recorder *MockBlobServiceMockRecorder
}

// MockBlobServiceMockRecorder is the mock recorder for MockBlobService.
type MockBlobServiceMockRecorder struct {
	mock *MockBlobService
}

// NewMockBlobService creates a new mock instance.
func NewMockBlobService(ctrl *gomock.Controller) *MockBlobService {
	mock := &MockBlobService{ctrl: ctrl}
	mock.recorder = &MockBlobServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlobService) EXPECT() *MockBlobServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockBlobService) Create(arg0 context.Context, arg1 *models.Blob) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockBlobServiceMockRecorder) Create(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBlobService)(nil).Create), arg0, arg1)
}

// DeleteByID mocks base method.
func (m *MockBlobService) DeleteByID(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockBlobServiceMockRecorder) DeleteByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockBlobService)(nil).DeleteByID), arg0, arg1)
}

// Exists mocks base method.
func (m *MockBlobService) Exists(arg0 context.Context, arg1 string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exists indicates an expected call of Exists.
func (mr *MockBlobServiceMockRecorder) Exists(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockBlobService)(nil).Exists), arg0, arg1)
}

// FindByDigest mocks base method.
func (m *MockBlobService) FindByDigest(arg0 context.Context, arg1 string) (*models.Blob, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindByDigest", arg0, arg1)
	ret0, _ := ret[0].(*models.Blob)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindByDigest indicates an expected call of FindByDigest.
func (mr *MockBlobServiceMockRecorder) FindByDigest(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindByDigest", reflect.TypeOf((*MockBlobService)(nil).FindByDigest), arg0, arg1)
}

// FindByDigests mocks base method.
func (m *MockBlobService) FindByDigests(arg0 context.Context, arg1 []string) ([]*models.Blob, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindByDigests", arg0, arg1)
	ret0, _ := ret[0].([]*models.Blob)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindByDigests indicates an expected call of FindByDigests.
func (mr *MockBlobServiceMockRecorder) FindByDigests(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindByDigests", reflect.TypeOf((*MockBlobService)(nil).FindByDigests), arg0, arg1)
}

// Incr mocks base method.
func (m *MockBlobService) Incr(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Incr", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Incr indicates an expected call of Incr.
func (mr *MockBlobServiceMockRecorder) Incr(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Incr", reflect.TypeOf((*MockBlobService)(nil).Incr), arg0, arg1)
}
