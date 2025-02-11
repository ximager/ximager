// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: WorkQueueServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/workq_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao WorkQueueServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockWorkQueueServiceFactory is a mock of WorkQueueServiceFactory interface.
type MockWorkQueueServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockWorkQueueServiceFactoryMockRecorder
	isgomock struct{}
}

// MockWorkQueueServiceFactoryMockRecorder is the mock recorder for MockWorkQueueServiceFactory.
type MockWorkQueueServiceFactoryMockRecorder struct {
	mock *MockWorkQueueServiceFactory
}

// NewMockWorkQueueServiceFactory creates a new mock instance.
func NewMockWorkQueueServiceFactory(ctrl *gomock.Controller) *MockWorkQueueServiceFactory {
	mock := &MockWorkQueueServiceFactory{ctrl: ctrl}
	mock.recorder = &MockWorkQueueServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWorkQueueServiceFactory) EXPECT() *MockWorkQueueServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockWorkQueueServiceFactory) New(txs ...*query.Query) dao.WorkQueueService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range txs {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.WorkQueueService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockWorkQueueServiceFactoryMockRecorder) New(txs ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockWorkQueueServiceFactory)(nil).New), txs...)
}
