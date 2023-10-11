// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: BlobUploadService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/blobupload.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao BlobUploadService
//
// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	models "github.com/go-sigma/sigma/pkg/dal/models"
	gomock "go.uber.org/mock/gomock"
)

// MockBlobUploadService is a mock of BlobUploadService interface.
type MockBlobUploadService struct {
	ctrl     *gomock.Controller
	recorder *MockBlobUploadServiceMockRecorder
}

// MockBlobUploadServiceMockRecorder is the mock recorder for MockBlobUploadService.
type MockBlobUploadServiceMockRecorder struct {
	mock *MockBlobUploadService
}

// NewMockBlobUploadService creates a new mock instance.
func NewMockBlobUploadService(ctrl *gomock.Controller) *MockBlobUploadService {
	mock := &MockBlobUploadService{ctrl: ctrl}
	mock.recorder = &MockBlobUploadServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlobUploadService) EXPECT() *MockBlobUploadServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockBlobUploadService) Create(arg0 context.Context, arg1 *models.BlobUpload) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockBlobUploadServiceMockRecorder) Create(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBlobUploadService)(nil).Create), arg0, arg1)
}

// DeleteByUploadID mocks base method.
func (m *MockBlobUploadService) DeleteByUploadID(arg0 context.Context, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByUploadID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByUploadID indicates an expected call of DeleteByUploadID.
func (mr *MockBlobUploadServiceMockRecorder) DeleteByUploadID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByUploadID", reflect.TypeOf((*MockBlobUploadService)(nil).DeleteByUploadID), arg0, arg1)
}

// FindAllByUploadID mocks base method.
func (m *MockBlobUploadService) FindAllByUploadID(arg0 context.Context, arg1 string) ([]*models.BlobUpload, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindAllByUploadID", arg0, arg1)
	ret0, _ := ret[0].([]*models.BlobUpload)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindAllByUploadID indicates an expected call of FindAllByUploadID.
func (mr *MockBlobUploadServiceMockRecorder) FindAllByUploadID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindAllByUploadID", reflect.TypeOf((*MockBlobUploadService)(nil).FindAllByUploadID), arg0, arg1)
}

// GetLastPart mocks base method.
func (m *MockBlobUploadService) GetLastPart(arg0 context.Context, arg1 string) (*models.BlobUpload, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLastPart", arg0, arg1)
	ret0, _ := ret[0].(*models.BlobUpload)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLastPart indicates an expected call of GetLastPart.
func (mr *MockBlobUploadServiceMockRecorder) GetLastPart(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLastPart", reflect.TypeOf((*MockBlobUploadService)(nil).GetLastPart), arg0, arg1)
}

// TotalEtagsByUploadID mocks base method.
func (m *MockBlobUploadService) TotalEtagsByUploadID(arg0 context.Context, arg1 string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TotalEtagsByUploadID", arg0, arg1)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TotalEtagsByUploadID indicates an expected call of TotalEtagsByUploadID.
func (mr *MockBlobUploadServiceMockRecorder) TotalEtagsByUploadID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TotalEtagsByUploadID", reflect.TypeOf((*MockBlobUploadService)(nil).TotalEtagsByUploadID), arg0, arg1)
}

// TotalSizeByUploadID mocks base method.
func (m *MockBlobUploadService) TotalSizeByUploadID(arg0 context.Context, arg1 string) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TotalSizeByUploadID", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TotalSizeByUploadID indicates an expected call of TotalSizeByUploadID.
func (mr *MockBlobUploadServiceMockRecorder) TotalSizeByUploadID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TotalSizeByUploadID", reflect.TypeOf((*MockBlobUploadService)(nil).TotalSizeByUploadID), arg0, arg1)
}
