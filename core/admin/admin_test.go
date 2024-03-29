/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package admin

import (
	"context"
	"fmt"
	"testing"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/testutil"
	"github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func init() {
	testutil.SetupTestConfig()
}

type mockValidator struct { // admin中有一个validate没有实现类，所以mock一个虚拟对象； 里面有个方法，再实现这个方法
	mock.Mock
}

func (v *mockValidator) validate(ctx context.Context, env *common.Envelope) (*pb.AdminOperation, error) {
	args := v.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	fmt.Println("here")
	return args.Get(0).(*pb.AdminOperation), nil // 强转
}

func TestGetStatus(t *testing.T) {
	adminServer := NewAdminServer(nil)   // admin Server
	adminServer.v = &mockValidator{}     //mocked object
	mv := adminServer.v.(*mockValidator) // 将mockValidator 转换为requestValidator
	//mv.On("validate").Return(nil, errors.New("error 不是nil")).Once() //意思是不是在下面的目标中调用了上面这个方法，然后是使用上面这个方法，而不是具体的方法
	mv.On("validate").Return(nil, nil)
	response, err := adminServer.GetStatus(context.Background(), nil)
	assert.NotNil(t, response, "Response should have been set")
	assert.Nil(t, err, "Error should have been nil")
}

func TestStartServer(t *testing.T) {
	adminServer := NewAdminServer(nil)
	adminServer.v = &mockValidator{}
	mv := adminServer.v.(*mockValidator)
	mv.On("validate").Return(nil, nil).Once()
	response, err := adminServer.StartServer(context.Background(), nil)
	assert.NotNil(t, response, "Response should have been set")
	assert.Nil(t, err, "Error should have been nil")
}

func TestForbidden(t *testing.T) { // 手动构造了一个错误
	adminServer := NewAdminServer(nil)
	adminServer.v = &mockValidator{}
	mv := adminServer.v.(*mockValidator)
	mv.On("validate").Return(nil, accessDenied).Times(5)
	//mv.On("validate").Return(nil, errors.New("error 不是nil")).Once()

	ctx := context.Background()
	status, err := adminServer.GetStatus(ctx, nil)
	assert.Nil(t, status)
	assert.Equal(t, accessDenied, err)

	ll, err := adminServer.GetModuleLogLevel(ctx, nil)
	assert.Nil(t, ll)
	assert.Equal(t, accessDenied, err)

	llr, err := adminServer.SetModuleLogLevel(ctx, nil)
	assert.Nil(t, llr)
	assert.Equal(t, accessDenied, err)

	_, err = adminServer.RevertLogLevels(ctx, nil)
	assert.Equal(t, accessDenied, err)

	_, err = adminServer.StartServer(ctx, nil)
	assert.Equal(t, accessDenied, err)
}

func TestLoggingCalls(t *testing.T) {
	adminServer := NewAdminServer(nil)
	adminServer.v = &mockValidator{}
	mv := adminServer.v.(*mockValidator)
	flogging.MustGetLogger("test")

	wrapLogLevelRequest := func(llr *pb.LogLevelRequest) *pb.AdminOperation {
		return &pb.AdminOperation{
			Content: &pb.AdminOperation_LogReq{
				LogReq: llr,
			},
		}
	}

	for _, llr := range []*pb.LogLevelRequest{{LogModule: "test"}, nil} {
		mv.On("validate").Return(wrapLogLevelRequest(llr), nil).Once()
		logResponse, err := adminServer.GetModuleLogLevel(context.Background(), nil)
		if llr == nil {
			assert.Nil(t, logResponse)
			assert.Equal(t, "request is nil", err.Error())
			continue
		}
		assert.NotNil(t, logResponse, "logResponse should have been set")
		assert.Equal(t, flogging.DefaultLevel(), logResponse.LogLevel, "logger level should have been the default")
		assert.Nil(t, err, "Error should have been nil")
	}

	for _, llr := range []*pb.LogLevelRequest{{LogModule: "test", LogLevel: "debug"}, nil} {
		mv.On("validate").Return(wrapLogLevelRequest(llr), nil).Once()
		logResponse, err := adminServer.SetModuleLogLevel(context.Background(), nil)
		if llr == nil {
			assert.Nil(t, logResponse)
			assert.Equal(t, "request is nil", err.Error())
			continue
		}
		assert.NotNil(t, logResponse, "logResponse should have been set")
		assert.Equal(t, "DEBUG", logResponse.LogLevel, "logger level should have been set to debug")
		assert.Nil(t, err, "Error should have been nil")
	}

	mv.On("validate").Return(nil, nil).Once()
	_, err := adminServer.RevertLogLevels(context.Background(), nil)
	assert.Nil(t, err, "Error should have been nil")

	mv.On("validate").Return(wrapLogLevelRequest(&pb.LogLevelRequest{LogModule: "test"}), nil).Once()
	logResponse, err := adminServer.GetModuleLogLevel(context.Background(), nil)
	assert.NotNil(t, logResponse, "logResponse should have been set")
	assert.Equal(t, flogging.DefaultLevel(), logResponse.LogLevel, "logger level should have been the default")
	assert.Nil(t, err, "Error should have been nil")
}
