// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: BlobUploadServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/blobupload_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao BlobUploadServiceFactory
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockBlobUploadServiceFactory is a mock of BlobUploadServiceFactory interface.
type MockBlobUploadServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockBlobUploadServiceFactoryMockRecorder
}

// MockBlobUploadServiceFactoryMockRecorder is the mock recorder for MockBlobUploadServiceFactory.
type MockBlobUploadServiceFactoryMockRecorder struct {
	mock *MockBlobUploadServiceFactory
}

// NewMockBlobUploadServiceFactory creates a new mock instance.
func NewMockBlobUploadServiceFactory(ctrl *gomock.Controller) *MockBlobUploadServiceFactory {
	mock := &MockBlobUploadServiceFactory{ctrl: ctrl}
	mock.recorder = &MockBlobUploadServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlobUploadServiceFactory) EXPECT() *MockBlobUploadServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockBlobUploadServiceFactory) New(arg0 ...*query.Query) dao.BlobUploadService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.BlobUploadService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockBlobUploadServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockBlobUploadServiceFactory)(nil).New), arg0...)
}
