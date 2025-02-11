// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: RepositoryServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/repository_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao RepositoryServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockRepositoryServiceFactory is a mock of RepositoryServiceFactory interface.
type MockRepositoryServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockRepositoryServiceFactoryMockRecorder
	isgomock struct{}
}

// MockRepositoryServiceFactoryMockRecorder is the mock recorder for MockRepositoryServiceFactory.
type MockRepositoryServiceFactoryMockRecorder struct {
	mock *MockRepositoryServiceFactory
}

// NewMockRepositoryServiceFactory creates a new mock instance.
func NewMockRepositoryServiceFactory(ctrl *gomock.Controller) *MockRepositoryServiceFactory {
	mock := &MockRepositoryServiceFactory{ctrl: ctrl}
	mock.recorder = &MockRepositoryServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepositoryServiceFactory) EXPECT() *MockRepositoryServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockRepositoryServiceFactory) New(txs ...*query.Query) dao.RepositoryService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range txs {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.RepositoryService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockRepositoryServiceFactoryMockRecorder) New(txs ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockRepositoryServiceFactory)(nil).New), txs...)
}
