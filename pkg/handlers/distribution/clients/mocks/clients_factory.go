// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/handlers/distribution/clients (interfaces: ClientsFactory)
//
// Generated by this command:
//
//	mockgen -destination=mocks/clients_factory.go -package=mocks github.com/go-sigma/sigma/pkg/handlers/distribution/clients ClientsFactory
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	configs "github.com/go-sigma/sigma/pkg/configs"
	clients "github.com/go-sigma/sigma/pkg/handlers/distribution/clients"
	gomock "go.uber.org/mock/gomock"
)

// MockClientsFactory is a mock of ClientsFactory interface.
type MockClientsFactory struct {
	ctrl     *gomock.Controller
	recorder *MockClientsFactoryMockRecorder
}

// MockClientsFactoryMockRecorder is the mock recorder for MockClientsFactory.
type MockClientsFactoryMockRecorder struct {
	mock *MockClientsFactory
}

// NewMockClientsFactory creates a new mock instance.
func NewMockClientsFactory(ctrl *gomock.Controller) *MockClientsFactory {
	mock := &MockClientsFactory{ctrl: ctrl}
	mock.recorder = &MockClientsFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientsFactory) EXPECT() *MockClientsFactoryMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockClientsFactory) New(arg0 configs.Configuration) (clients.Clients, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New", arg0)
	ret0, _ := ret[0].(clients.Clients)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockClientsFactoryMockRecorder) New(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockClientsFactory)(nil).New), arg0)
}
