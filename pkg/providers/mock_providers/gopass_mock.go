// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/providers/gopass.go

// Package mock_providers is a generated GoMock package.
package mock_providers

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	gopass "github.com/gopasspw/gopass/pkg/gopass"
	reflect "reflect"
)

// MockGopassClient is a mock of GopassClient interface
type MockGopassClient struct {
	ctrl     *gomock.Controller
	recorder *MockGopassClientMockRecorder
}

// MockGopassClientMockRecorder is the mock recorder for MockGopassClient
type MockGopassClientMockRecorder struct {
	mock *MockGopassClient
}

// NewMockGopassClient creates a new mock instance
func NewMockGopassClient(ctrl *gomock.Controller) *MockGopassClient {
	mock := &MockGopassClient{ctrl: ctrl}
	mock.recorder = &MockGopassClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockGopassClient) EXPECT() *MockGopassClientMockRecorder {
	return m.recorder
}

// List mocks base method
func (m *MockGopassClient) List(ctx context.Context) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List
func (mr *MockGopassClientMockRecorder) List(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockGopassClient)(nil).List), ctx)
}

// Get mocks base method
func (m *MockGopassClient) Get(ctx context.Context, name, revision string) (gopass.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, name, revision)
	ret0, _ := ret[0].(gopass.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get
func (mr *MockGopassClientMockRecorder) Get(ctx, name, revision interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockGopassClient)(nil).Get), ctx, name, revision)
}

// Set mocks base method
func (m *MockGopassClient) Set(ctx context.Context, name string, sec gopass.Byter) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Set", ctx, name, sec)
	ret0, _ := ret[0].(error)
	return ret0
}

// Set indicates an expected call of Set
func (mr *MockGopassClientMockRecorder) Set(ctx, name, sec interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Set", reflect.TypeOf((*MockGopassClient)(nil).Set), ctx, name, sec)
}
