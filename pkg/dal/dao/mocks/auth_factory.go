// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: AuthServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/auth_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao AuthServiceFactory
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockAuthServiceFactory is a mock of AuthServiceFactory interface.
type MockAuthServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockAuthServiceFactoryMockRecorder
}

// MockAuthServiceFactoryMockRecorder is the mock recorder for MockAuthServiceFactory.
type MockAuthServiceFactoryMockRecorder struct {
	mock *MockAuthServiceFactory
}

// NewMockAuthServiceFactory creates a new mock instance.
func NewMockAuthServiceFactory(ctrl *gomock.Controller) *MockAuthServiceFactory {
	mock := &MockAuthServiceFactory{ctrl: ctrl}
	mock.recorder = &MockAuthServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthServiceFactory) EXPECT() *MockAuthServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockAuthServiceFactory) New(arg0 ...*query.Query) dao.AuthService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.AuthService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockAuthServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockAuthServiceFactory)(nil).New), arg0...)
}
