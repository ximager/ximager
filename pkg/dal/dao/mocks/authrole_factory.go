// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: AuthRoleServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/authrole_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao AuthRoleServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockAuthRoleServiceFactory is a mock of AuthRoleServiceFactory interface.
type MockAuthRoleServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockAuthRoleServiceFactoryMockRecorder
}

// MockAuthRoleServiceFactoryMockRecorder is the mock recorder for MockAuthRoleServiceFactory.
type MockAuthRoleServiceFactoryMockRecorder struct {
	mock *MockAuthRoleServiceFactory
}

// NewMockAuthRoleServiceFactory creates a new mock instance.
func NewMockAuthRoleServiceFactory(ctrl *gomock.Controller) *MockAuthRoleServiceFactory {
	mock := &MockAuthRoleServiceFactory{ctrl: ctrl}
	mock.recorder = &MockAuthRoleServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthRoleServiceFactory) EXPECT() *MockAuthRoleServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockAuthRoleServiceFactory) New(arg0 ...*query.Query) dao.AuthRoleService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.AuthRoleService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockAuthRoleServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockAuthRoleServiceFactory)(nil).New), arg0...)
}
