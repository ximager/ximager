// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: CodeRepositoryServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/code_repository_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao CodeRepositoryServiceFactory
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockCodeRepositoryServiceFactory is a mock of CodeRepositoryServiceFactory interface.
type MockCodeRepositoryServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockCodeRepositoryServiceFactoryMockRecorder
}

// MockCodeRepositoryServiceFactoryMockRecorder is the mock recorder for MockCodeRepositoryServiceFactory.
type MockCodeRepositoryServiceFactoryMockRecorder struct {
	mock *MockCodeRepositoryServiceFactory
}

// NewMockCodeRepositoryServiceFactory creates a new mock instance.
func NewMockCodeRepositoryServiceFactory(ctrl *gomock.Controller) *MockCodeRepositoryServiceFactory {
	mock := &MockCodeRepositoryServiceFactory{ctrl: ctrl}
	mock.recorder = &MockCodeRepositoryServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodeRepositoryServiceFactory) EXPECT() *MockCodeRepositoryServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockCodeRepositoryServiceFactory) New(arg0 ...*query.Query) dao.CodeRepositoryService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.CodeRepositoryService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockCodeRepositoryServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockCodeRepositoryServiceFactory)(nil).New), arg0...)
}
