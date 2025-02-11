// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/modules/locker/definition (interfaces: Locker)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"
	time "time"

	definition "github.com/go-sigma/sigma/pkg/modules/locker/definition"
	gomock "github.com/golang/mock/gomock"
)

// MockLocker is a mock of Locker interface.
type MockLocker struct {
	ctrl     *gomock.Controller
	recorder *MockLockerMockRecorder
}

// MockLockerMockRecorder is the mock recorder for MockLocker.
type MockLockerMockRecorder struct {
	mock *MockLocker
}

// NewMockLocker creates a new mock instance.
func NewMockLocker(ctrl *gomock.Controller) *MockLocker {
	mock := &MockLocker{ctrl: ctrl}
	mock.recorder = &MockLockerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLocker) EXPECT() *MockLockerMockRecorder {
	return m.recorder
}

// Acquire mocks base method.
func (m *MockLocker) Acquire(arg0 context.Context, arg1 string, arg2, arg3 time.Duration) (definition.Lock, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Acquire", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(definition.Lock)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Acquire indicates an expected call of Acquire.
func (mr *MockLockerMockRecorder) Acquire(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Acquire", reflect.TypeOf((*MockLocker)(nil).Acquire), arg0, arg1, arg2, arg3)
}

// AcquireWithRenew mocks base method.
func (m *MockLocker) AcquireWithRenew(arg0 context.Context, arg1 string, arg2, arg3 time.Duration) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AcquireWithRenew", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AcquireWithRenew indicates an expected call of AcquireWithRenew.
func (mr *MockLockerMockRecorder) AcquireWithRenew(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AcquireWithRenew", reflect.TypeOf((*MockLocker)(nil).AcquireWithRenew), arg0, arg1, arg2, arg3)
}
