// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: DaemonServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/daemon_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao DaemonServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockDaemonServiceFactory is a mock of DaemonServiceFactory interface.
type MockDaemonServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockDaemonServiceFactoryMockRecorder
}

// MockDaemonServiceFactoryMockRecorder is the mock recorder for MockDaemonServiceFactory.
type MockDaemonServiceFactoryMockRecorder struct {
	mock *MockDaemonServiceFactory
}

// NewMockDaemonServiceFactory creates a new mock instance.
func NewMockDaemonServiceFactory(ctrl *gomock.Controller) *MockDaemonServiceFactory {
	mock := &MockDaemonServiceFactory{ctrl: ctrl}
	mock.recorder = &MockDaemonServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDaemonServiceFactory) EXPECT() *MockDaemonServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockDaemonServiceFactory) New(arg0 ...*query.Query) dao.DaemonService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.DaemonService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockDaemonServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockDaemonServiceFactory)(nil).New), arg0...)
}
