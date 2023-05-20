// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ximager/ximager/pkg/dal/dao (interfaces: ReferenceService)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/ximager/ximager/pkg/dal/models"
)

// MockReferenceService is a mock of ReferenceService interface.
type MockReferenceService struct {
	ctrl     *gomock.Controller
	recorder *MockReferenceServiceMockRecorder
}

// MockReferenceServiceMockRecorder is the mock recorder for MockReferenceService.
type MockReferenceServiceMockRecorder struct {
	mock *MockReferenceService
}

// NewMockReferenceService creates a new mock instance.
func NewMockReferenceService(ctrl *gomock.Controller) *MockReferenceService {
	mock := &MockReferenceService{ctrl: ctrl}
	mock.recorder = &MockReferenceServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReferenceService) EXPECT() *MockReferenceServiceMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *MockReferenceService) Get(arg0 context.Context, arg1, arg2 string) (*models.Reference, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1, arg2)
	ret0, _ := ret[0].(*models.Reference)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockReferenceServiceMockRecorder) Get(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockReferenceService)(nil).Get), arg0, arg1, arg2)
}
