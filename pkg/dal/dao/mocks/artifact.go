// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/go-sigma/sigma/pkg/dal/dao (interfaces: ArtifactService)
//
// Generated by this command:
//
//	mockgen -destination=mocks/artifact.go -package=mocks github.com/go-sigma/sigma/pkg/dal/dao ArtifactService
//
// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"
	time "time"

	models "github.com/go-sigma/sigma/pkg/dal/models"
	types "github.com/go-sigma/sigma/pkg/types"
	gomock "go.uber.org/mock/gomock"
)

// MockArtifactService is a mock of ArtifactService interface.
type MockArtifactService struct {
	ctrl     *gomock.Controller
	recorder *MockArtifactServiceMockRecorder
}

// MockArtifactServiceMockRecorder is the mock recorder for MockArtifactService.
type MockArtifactServiceMockRecorder struct {
	mock *MockArtifactService
}

// NewMockArtifactService creates a new mock instance.
func NewMockArtifactService(ctrl *gomock.Controller) *MockArtifactService {
	mock := &MockArtifactService{ctrl: ctrl}
	mock.recorder = &MockArtifactServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockArtifactService) EXPECT() *MockArtifactServiceMockRecorder {
	return m.recorder
}

// AssociateArtifact mocks base method.
func (m *MockArtifactService) AssociateArtifact(arg0 context.Context, arg1 *models.Artifact, arg2 []*models.Artifact) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssociateArtifact", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AssociateArtifact indicates an expected call of AssociateArtifact.
func (mr *MockArtifactServiceMockRecorder) AssociateArtifact(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssociateArtifact", reflect.TypeOf((*MockArtifactService)(nil).AssociateArtifact), arg0, arg1, arg2)
}

// AssociateBlobs mocks base method.
func (m *MockArtifactService) AssociateBlobs(arg0 context.Context, arg1 *models.Artifact, arg2 []*models.Blob) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AssociateBlobs", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// AssociateBlobs indicates an expected call of AssociateBlobs.
func (mr *MockArtifactServiceMockRecorder) AssociateBlobs(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssociateBlobs", reflect.TypeOf((*MockArtifactService)(nil).AssociateBlobs), arg0, arg1, arg2)
}

// CountArtifact mocks base method.
func (m *MockArtifactService) CountArtifact(arg0 context.Context, arg1 types.ListArtifactRequest) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountArtifact", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountArtifact indicates an expected call of CountArtifact.
func (mr *MockArtifactServiceMockRecorder) CountArtifact(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountArtifact", reflect.TypeOf((*MockArtifactService)(nil).CountArtifact), arg0, arg1)
}

// CountByNamespace mocks base method.
func (m *MockArtifactService) CountByNamespace(arg0 context.Context, arg1 []int64) (map[int64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByNamespace", arg0, arg1)
	ret0, _ := ret[0].(map[int64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByNamespace indicates an expected call of CountByNamespace.
func (mr *MockArtifactServiceMockRecorder) CountByNamespace(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByNamespace", reflect.TypeOf((*MockArtifactService)(nil).CountByNamespace), arg0, arg1)
}

// CountByRepository mocks base method.
func (m *MockArtifactService) CountByRepository(arg0 context.Context, arg1 []int64) (map[int64]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CountByRepository", arg0, arg1)
	ret0, _ := ret[0].(map[int64]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CountByRepository indicates an expected call of CountByRepository.
func (mr *MockArtifactServiceMockRecorder) CountByRepository(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CountByRepository", reflect.TypeOf((*MockArtifactService)(nil).CountByRepository), arg0, arg1)
}

// Create mocks base method.
func (m *MockArtifactService) Create(arg0 context.Context, arg1 *models.Artifact) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockArtifactServiceMockRecorder) Create(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockArtifactService)(nil).Create), arg0, arg1)
}

// CreateSbom mocks base method.
func (m *MockArtifactService) CreateSbom(arg0 context.Context, arg1 *models.ArtifactSbom) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSbom", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateSbom indicates an expected call of CreateSbom.
func (mr *MockArtifactServiceMockRecorder) CreateSbom(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSbom", reflect.TypeOf((*MockArtifactService)(nil).CreateSbom), arg0, arg1)
}

// CreateVulnerability mocks base method.
func (m *MockArtifactService) CreateVulnerability(arg0 context.Context, arg1 *models.ArtifactVulnerability) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateVulnerability", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateVulnerability indicates an expected call of CreateVulnerability.
func (mr *MockArtifactServiceMockRecorder) CreateVulnerability(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateVulnerability", reflect.TypeOf((*MockArtifactService)(nil).CreateVulnerability), arg0, arg1)
}

// DeleteByDigest mocks base method.
func (m *MockArtifactService) DeleteByDigest(arg0 context.Context, arg1, arg2 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByDigest", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByDigest indicates an expected call of DeleteByDigest.
func (mr *MockArtifactServiceMockRecorder) DeleteByDigest(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByDigest", reflect.TypeOf((*MockArtifactService)(nil).DeleteByDigest), arg0, arg1, arg2)
}

// DeleteByID mocks base method.
func (m *MockArtifactService) DeleteByID(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByID", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByID indicates an expected call of DeleteByID.
func (mr *MockArtifactServiceMockRecorder) DeleteByID(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByID", reflect.TypeOf((*MockArtifactService)(nil).DeleteByID), arg0, arg1)
}

// DeleteByIDs mocks base method.
func (m *MockArtifactService) DeleteByIDs(arg0 context.Context, arg1 []int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteByIDs", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteByIDs indicates an expected call of DeleteByIDs.
func (mr *MockArtifactServiceMockRecorder) DeleteByIDs(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteByIDs", reflect.TypeOf((*MockArtifactService)(nil).DeleteByIDs), arg0, arg1)
}

// FindAssociateWithArtifact mocks base method.
func (m *MockArtifactService) FindAssociateWithArtifact(arg0 context.Context, arg1 []int64) ([]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindAssociateWithArtifact", arg0, arg1)
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindAssociateWithArtifact indicates an expected call of FindAssociateWithArtifact.
func (mr *MockArtifactServiceMockRecorder) FindAssociateWithArtifact(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindAssociateWithArtifact", reflect.TypeOf((*MockArtifactService)(nil).FindAssociateWithArtifact), arg0, arg1)
}

// FindAssociateWithTag mocks base method.
func (m *MockArtifactService) FindAssociateWithTag(arg0 context.Context, arg1 []int64) ([]int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindAssociateWithTag", arg0, arg1)
	ret0, _ := ret[0].([]int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindAssociateWithTag indicates an expected call of FindAssociateWithTag.
func (mr *MockArtifactServiceMockRecorder) FindAssociateWithTag(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindAssociateWithTag", reflect.TypeOf((*MockArtifactService)(nil).FindAssociateWithTag), arg0, arg1)
}

// FindWithLastPull mocks base method.
func (m *MockArtifactService) FindWithLastPull(arg0 context.Context, arg1 int64, arg2 time.Time, arg3, arg4 int64) ([]*models.Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FindWithLastPull", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*models.Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindWithLastPull indicates an expected call of FindWithLastPull.
func (mr *MockArtifactServiceMockRecorder) FindWithLastPull(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindWithLastPull", reflect.TypeOf((*MockArtifactService)(nil).FindWithLastPull), arg0, arg1, arg2, arg3, arg4)
}

// Get mocks base method.
func (m *MockArtifactService) Get(arg0 context.Context, arg1 int64) (*models.Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*models.Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockArtifactServiceMockRecorder) Get(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockArtifactService)(nil).Get), arg0, arg1)
}

// GetByDigest mocks base method.
func (m *MockArtifactService) GetByDigest(arg0 context.Context, arg1 int64, arg2 string) (*models.Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByDigest", arg0, arg1, arg2)
	ret0, _ := ret[0].(*models.Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByDigest indicates an expected call of GetByDigest.
func (mr *MockArtifactServiceMockRecorder) GetByDigest(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByDigest", reflect.TypeOf((*MockArtifactService)(nil).GetByDigest), arg0, arg1, arg2)
}

// GetByDigests mocks base method.
func (m *MockArtifactService) GetByDigests(arg0 context.Context, arg1 string, arg2 []string) ([]*models.Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByDigests", arg0, arg1, arg2)
	ret0, _ := ret[0].([]*models.Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByDigests indicates an expected call of GetByDigests.
func (mr *MockArtifactServiceMockRecorder) GetByDigests(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByDigests", reflect.TypeOf((*MockArtifactService)(nil).GetByDigests), arg0, arg1, arg2)
}

// GetNamespaceSize mocks base method.
func (m *MockArtifactService) GetNamespaceSize(arg0 context.Context, arg1 int64) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespaceSize", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNamespaceSize indicates an expected call of GetNamespaceSize.
func (mr *MockArtifactServiceMockRecorder) GetNamespaceSize(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespaceSize", reflect.TypeOf((*MockArtifactService)(nil).GetNamespaceSize), arg0, arg1)
}

// GetRepositorySize mocks base method.
func (m *MockArtifactService) GetRepositorySize(arg0 context.Context, arg1 int64) (int64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRepositorySize", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRepositorySize indicates an expected call of GetRepositorySize.
func (mr *MockArtifactServiceMockRecorder) GetRepositorySize(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRepositorySize", reflect.TypeOf((*MockArtifactService)(nil).GetRepositorySize), arg0, arg1)
}

// Incr mocks base method.
func (m *MockArtifactService) Incr(arg0 context.Context, arg1 int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Incr", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Incr indicates an expected call of Incr.
func (mr *MockArtifactServiceMockRecorder) Incr(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Incr", reflect.TypeOf((*MockArtifactService)(nil).Incr), arg0, arg1)
}

// ListArtifact mocks base method.
func (m *MockArtifactService) ListArtifact(arg0 context.Context, arg1 types.ListArtifactRequest) ([]*models.Artifact, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListArtifact", arg0, arg1)
	ret0, _ := ret[0].([]*models.Artifact)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListArtifact indicates an expected call of ListArtifact.
func (mr *MockArtifactServiceMockRecorder) ListArtifact(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListArtifact", reflect.TypeOf((*MockArtifactService)(nil).ListArtifact), arg0, arg1)
}

// UpdateSbom mocks base method.
func (m *MockArtifactService) UpdateSbom(arg0 context.Context, arg1 int64, arg2 map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSbom", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSbom indicates an expected call of UpdateSbom.
func (mr *MockArtifactServiceMockRecorder) UpdateSbom(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSbom", reflect.TypeOf((*MockArtifactService)(nil).UpdateSbom), arg0, arg1, arg2)
}

// UpdateVulnerability mocks base method.
func (m *MockArtifactService) UpdateVulnerability(arg0 context.Context, arg1 int64, arg2 map[string]any) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateVulnerability", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateVulnerability indicates an expected call of UpdateVulnerability.
func (mr *MockArtifactServiceMockRecorder) UpdateVulnerability(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateVulnerability", reflect.TypeOf((*MockArtifactService)(nil).UpdateVulnerability), arg0, arg1, arg2)
}
