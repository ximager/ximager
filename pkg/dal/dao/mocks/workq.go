// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: WorkQueueService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/workq.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao WorkQueueService
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	models "github.com/go-sigma/sigma/pkg/dal/models"
	enums "github.com/go-sigma/sigma/pkg/types/enums"
	gomock "go.uber.org/mock/gomock"
)

// MockWorkQueueService is a mock of WorkQueueService interface.
type MockWorkQueueService struct {
	ctrl     *gomock.Controller
	recorder *MockWorkQueueServiceMockRecorder
	isgomock struct{}
}

// MockWorkQueueServiceMockRecorder is the mock recorder for MockWorkQueueService.
type MockWorkQueueServiceMockRecorder struct {
	mock *MockWorkQueueService
}

// NewMockWorkQueueService creates a new mock instance.
func NewMockWorkQueueService(ctrl *gomock.Controller) *MockWorkQueueService {
	mock := &MockWorkQueueService{ctrl: ctrl}
	mock.recorder = &MockWorkQueueServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWorkQueueService) EXPECT() *MockWorkQueueServiceMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockWorkQueueService) Create(ctx context.Context, workqObj *models.WorkQueue) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, workqObj)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockWorkQueueServiceMockRecorder) Create(ctx, workqObj any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockWorkQueueService)(nil).Create), ctx, workqObj)
}

// Get mocks base method.
func (m *MockWorkQueueService) Get(ctx context.Context, topic enums.Daemon) (*models.WorkQueue, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, topic)
	ret0, _ := ret[0].(*models.WorkQueue)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockWorkQueueServiceMockRecorder) Get(ctx, topic any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockWorkQueueService)(nil).Get), ctx, topic)
}

// UpdateStatus mocks base method.
func (m *MockWorkQueueService) UpdateStatus(ctx context.Context, id int64, version, newVersion string, times int, status enums.TaskCommonStatus) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateStatus", ctx, id, version, newVersion, times, status)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateStatus indicates an expected call of UpdateStatus.
func (mr *MockWorkQueueServiceMockRecorder) UpdateStatus(ctx, id, version, newVersion, times, status any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateStatus", reflect.TypeOf((*MockWorkQueueService)(nil).UpdateStatus), ctx, id, version, newVersion, times, status)
}
