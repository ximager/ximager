// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: WebhookServiceFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/webhook_factory.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao WebhookServiceFactory
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	dao "github.com/go-sigma/sigma/pkg/dal/dao"
	query "github.com/go-sigma/sigma/pkg/dal/query"
	gomock "go.uber.org/mock/gomock"
)

// MockWebhookServiceFactory is a mock of WebhookServiceFactory interface.
type MockWebhookServiceFactory struct {
	ctrl     *gomock.Controller
	recorder *MockWebhookServiceFactoryMockRecorder
}

// MockWebhookServiceFactoryMockRecorder is the mock recorder for MockWebhookServiceFactory.
type MockWebhookServiceFactoryMockRecorder struct {
	mock *MockWebhookServiceFactory
}

// NewMockWebhookServiceFactory creates a new mock instance.
func NewMockWebhookServiceFactory(ctrl *gomock.Controller) *MockWebhookServiceFactory {
	mock := &MockWebhookServiceFactory{ctrl: ctrl}
	mock.recorder = &MockWebhookServiceFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWebhookServiceFactory) EXPECT() *MockWebhookServiceFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockWebhookServiceFactory) New(arg0 ...*query.Query) dao.WebhookService {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range arg0 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "New", varargs...)
	ret0, _ := ret[0].(dao.WebhookService)
	return ret0
}

// New indicates an expected call of New.
func (mr *MockWebhookServiceFactoryMockRecorder) New(arg0 ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockWebhookServiceFactory)(nil).New), arg0...)
}
