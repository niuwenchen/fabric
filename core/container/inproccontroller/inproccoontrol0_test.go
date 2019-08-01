package inproccontroller

import (
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/container/ccintf"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/stretchr/testify/assert"
	"testing"
)

type Mock0Shim struct {

}

func (shim Mock0Shim) Init(stub shim.ChaincodeStubInterface) pb.Response{
	return pb.Response{}
}

func (shim Mock0Shim) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	return pb.Response{}
}
type MockChaincodeSupport struct {

}

func (support MockChaincodeSupport) HandleChaincodeStream(stream ccintf.ChaincodeStream)  error{
	return nil
}


func Test0Error(t *testing.T){
	err := SysCCRegisteredErr("error")
	//println(err.Error())
	assert.Regexp(t,"already registered",err.Error(),"message should be correct")

}


func Test0RegisterSuccess(t *testing.T){
	r :=NewRegistry()
	r.ChaincodeSupport = MockChaincodeSupport{}
	shim := Mock0Shim{}
	err := r.Register(&ccintf.CCID{Name:"JackNiu"},shim)

	assert.Nil(t, err, "err should be nil")
	assert.Equal(t, r.typeRegistry["JackNiu"].chaincode, shim, "shim should be correct")

	// 现在需要测试的是方法Register，需要的参数如上
	//构造完了，认为这个方法没有错误，那么返回值就是Nil； 再就是判断里面的参数，如等于
	// 这个方法的本质试讲chaincode 注册到了container中，那么这里就是判断是否注册成功

}
//测试注册失败,就是测试里面的if分支,
func TestRegisterError0(t *testing.T){
	r := NewRegistry()
	r.ChaincodeSupport = MockCCSupport{}
	r.typeRegistry["name"] = &inprocContainer{}
	shim := MockShim{}
	err := r.Register(&ccintf.CCID{Name: "name"}, shim)

	assert.NotNil(t, err, "err should not be nil")

}

type AStruct0 struct {
}

type AInterface0 interface {
	test()
}

func (as AStruct0) test() {}


func TestGetInstanceChaincodeDoesntExist0(t *testing.T){
	mockInproccontroller := &inprocContainer{chaincode:Mock0Shim{}}   //chaincode: 代表的就是链码
	r := NewRegistry()
	r.ChaincodeSupport = MockCCSupport{}
	vm := NewInprocVM(r)
	args := []string{"a", "b"}
	env := []string{"a", "b"}

	container,err :=vm.getInstance(mockInproccontroller,"instName",args,env)
	assert.NotNil(t, container, "container should not be nil")
	assert.Nil(t, err, "err should be nil")

	if _,ok :=r.instRegistry["instName"]; ok{   //如果不ok的话 也就是没有返回的话 进行下面的输出
		fmt.Println("correct key hasnt been set on instRegistry")
	}


}

func TestGetInstaceChaincodeExists0(t *testing.T){
	mockInproccontroller := &inprocContainer{chaincode:Mock0Shim{}}   //chaincode: 代表的就是链码
	r := NewRegistry()
	r.ChaincodeSupport = MockCCSupport{}
	vm := NewInprocVM(r)

	args := []string{"a", "b"}
	env := []string{"a", "b"}

	ipc := &inprocContainer{args: args, env: env, chaincode: mockInproccontroller.chaincode, stopChan: make(chan struct{})}
	r.instRegistry["instName"]= ipc


	container,err :=vm.getInstance(mockInproccontroller,"instName",args,env)
	assert.NotNil(t, container, "container should not be nil")
	assert.Nil(t, err, "err should be nil")

	assert.Equal(t, r.instRegistry["instName"], ipc, "instRegistry[instName] should contain the correct value")

}


type MockReader0 struct {
}

func (r MockReader0) Read(p []byte) (n int, err error) {
	return 1, nil
}

// 测试登录proc  没有参数
func TestLaunchprocNoArgs0(t *testing.T){

}