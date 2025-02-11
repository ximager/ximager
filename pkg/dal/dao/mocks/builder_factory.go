// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: BuilderServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/builder_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao BuilderServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockBuilderServiceFactory is a mock of BuilderServiceFactory interface.
type MockBuilderServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockBuilderServiceFactoryMockRecorder
	isgomock struct{}
}

// MockBuilderServiceFactoryMockRecorder is the mock recorder for MockBuilderServiceFactory.
type MockBuilderServiceFactoryMockRecorder struct {
	mock *MockBuilderServiceFactory
}

// NewMockBuilderServiceFactory creates a new mock instance.
func NewMockBuilderServiceFactory(ctrl *gomock.Controller) *MockBuilderServiceFactory {
	mock := &MockBuilderServiceFactory{ctrl: ctrl}
	mock.recorder = &MockBuilderServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBuilderServiceFactory) EXPECT() *MockBuilderServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockBuilderServiceFactory) New(txs ...*query.Query) dao.BuilderService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range txs {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.BuilderService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockBuilderServiceFactoryMockRecorder) New(txs ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockBuilderServiceFactory)(nil).New), txs...)
}
