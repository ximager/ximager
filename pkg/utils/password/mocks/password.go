// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/utils/password (interfaces: Password)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockPassword is a mock of Password interface.
type MockPassword struct {
	ctrl     *gomock.Controller
	recorder *MockPasswordMockRecorder
}

// MockPasswordMockRecorder is the mock recorder for MockPassword.
type MockPasswordMockRecorder struct {
	mock *MockPassword
}

// NewMockPassword creates a new mock instance.
func NewMockPassword(ctrl *gomock.Controller) *MockPassword {
	mock := &MockPassword{ctrl: ctrl}
	mock.recorder = &MockPasswordMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPassword) EXPECT() *MockPasswordMockRecorder {
	return m.recorder
}

// Hash mocks base method.
func (m *MockPassword) Hash(arg0 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Hash", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Hash indicates an expected call of Hash.
func (mr *MockPasswordMockRecorder) Hash(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Hash", reflect.TypeOf((*MockPassword)(nil).Hash), arg0)
}

// Verify mocks base method.
func (m *MockPassword) Verify(arg0, arg1 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockPasswordMockRecorder) Verify(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockPassword)(nil).Verify), arg0, arg1)
}
