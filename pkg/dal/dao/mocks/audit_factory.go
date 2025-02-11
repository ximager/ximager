// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: AuditServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/audit_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao AuditServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockAuditServiceFactory is a mock of AuditServiceFactory interface.
type MockAuditServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockAuditServiceFactoryMockRecorder
	isgomock struct{}
}

// MockAuditServiceFactoryMockRecorder is the mock recorder for MockAuditServiceFactory.
type MockAuditServiceFactoryMockRecorder struct {
	mock *MockAuditServiceFactory
}

// NewMockAuditServiceFactory creates a new mock instance.
func NewMockAuditServiceFactory(ctrl *gomock.Controller) *MockAuditServiceFactory {
	mock := &MockAuditServiceFactory{ctrl: ctrl}
	mock.recorder = &MockAuditServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuditServiceFactory) EXPECT() *MockAuditServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockAuditServiceFactory) New(txs ...*query.Query) dao.AuditService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range txs {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.AuditService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockAuditServiceFactoryMockRecorder) New(txs ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockAuditServiceFactory)(nil).New), txs...)
}
