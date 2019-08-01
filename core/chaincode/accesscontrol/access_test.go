/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesscontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/common/flogging/floggingtest"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ccSrv struct {
	l              net.Listener
	grpcSrv        *grpc.Server
	t              *testing.T
	cert           []byte
	expectedCCname string
}

func (cs *ccSrv) Register(stream pb.ChaincodeSupport_RegisterServer) error { //Register(ChaincodeSupport_RegisterServer) error 既然ccSrv实现了Register函数，那么该结构体就是ChaincodeSupportServer的实例
	println("收到消息")
	println("调用Register")
	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	// First message is a register message
	assert.Equal(cs.t, pb.ChaincodeMessage_REGISTER.String(), msg.Type.String())
	// And its chaincode name is the expected one
	chaincodeID := &pb.ChaincodeID{}
	err = proto.Unmarshal(msg.Payload, chaincodeID)
	if err != nil {
		return err
	}
	assert.Equal(cs.t, cs.expectedCCname, chaincodeID.Name)
	// Subsequent messages are just echoed back
	for {
		msg, _ = stream.Recv()
		if err != nil {
			return err
		}
		err = stream.Send(msg)
		if err != nil {
			return err
		}
	}
}

func (cs *ccSrv) stop() {
	cs.grpcSrv.Stop()
	cs.l.Close()
}

func createTLSService(t *testing.T, ca tlsgen.CA, host string) *grpc.Server {
	keyPair, err := ca.NewServerCertKeyPair(host)
	cert, err := tls.X509KeyPair(keyPair.Cert, keyPair.Key)
	assert.NoError(t, err)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}
	tlsConf.ClientCAs.AppendCertsFromPEM(ca.CertBytes())
	return grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConf)))
}

func newCCServer(t *testing.T, port int, expectedCCname string, withTLS bool, ca tlsgen.CA) *ccSrv {
	var s *grpc.Server
	if withTLS {
		s = createTLSService(t, ca, "localhost")
	} else {
		s = grpc.NewServer()
	}

	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", "", port))
	assert.NoError(t, err, "%v", err)
	return &ccSrv{
		expectedCCname: expectedCCname,
		l:              l,
		grpcSrv:        s,
	}
}

type ccClient struct {
	conn   *grpc.ClientConn
	stream pb.ChaincodeSupport_RegisterClient
}

func newClient(t *testing.T, port int, cert *tls.Certificate, peerCACert []byte) (*ccClient, error) {
	tlsCfg := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	tlsCfg.RootCAs.AppendCertsFromPEM(peerCACert)
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	tlsOpts := grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, fmt.Sprintf("localhost:%d", port), tlsOpts, grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	chaincodeSupportClient := pb.NewChaincodeSupportClient(conn)
	client, err := chaincodeSupportClient.Register(context.Background()) //这里的Register是调用server端的方法，就是类似于SayGello函数，只是这里没有参数而已
	assert.NoError(t, err)

	return &ccClient{
		conn:   conn,
		stream: client,
	}, nil
}

func (c *ccClient) close() {
	c.conn.Close()
}

func (c *ccClient) sendMsg(msg *pb.ChaincodeMessage) {
	c.stream.Send(msg)
}

func (c *ccClient) recv() *pb.ChaincodeMessage {
	msgs := make(chan *pb.ChaincodeMessage, 1)
	go func() {
		msg, _ := c.stream.Recv()
		println("收到消息了吗？")
		if msg != nil {
			msgs <- msg
		}
	}()
	println("获取认证")
	select {
	case <-time.After(time.Second):
		println("yyy")
		return nil
	case msg := <-msgs:
		println("xxx", msg)
		return msg
	}
}

func Test01(t *testing.T) {
	chaincodeId := &pb.ChaincodeID{Name: "example02"} //0xc420028df0
	payload, err := proto.Marshal(chaincodeId)
	if err != nil {
		println("")
	}
	println(payload)
}

func TestAccessControl(t *testing.T) {
	backupTTL := ttl
	defer func() {
		ttl = backupTTL
	}()
	ttl = time.Second * 3

	oldLogger := logger
	l, recorder := floggingtest.NewTestLogger(t, floggingtest.AtLevel(zapcore.InfoLevel))
	logger = l
	defer func() { logger = oldLogger }()

	chaincodeID := &pb.ChaincodeID{Name: "example02"}
	payload, err := proto.Marshal(chaincodeID)
	println(payload)
	registerMsg := &pb.ChaincodeMessage{
		Type:    pb.ChaincodeMessage_REGISTER,
		Payload: payload,
	}
	putStateMsg := &pb.ChaincodeMessage{
		Type: pb.ChaincodeMessage_PUT_STATE,
	}

	ca, _ := tlsgen.NewCA()
	srv := newCCServer(t, 7052, "example02", true, ca)
	auth := NewAuthenticator(ca)
	pb.RegisterChaincodeSupportServer(srv.grpcSrv, auth.Wrap(srv)) //auth.Wrap函数 需要的参数是ChaincodeSupportSevrer,
	go srv.grpcSrv.Serve(srv.l)                                    //启动服务
	defer srv.stop()

	println("0001------------>")
	//第一个测试的  ctx 获取时间超时
	// Create an attacker without a TLS certificate
	_, err = newClient(t, 7052, nil, ca.CertBytes())
	println("err", err.Error())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")

	println("0002------------>")
	// Create an attacker with its own TLS certificate
	maliciousCA, _ := tlsgen.NewCA()
	keyPair, err := maliciousCA.NewClientCertKeyPair()
	//println("AAAA",string(keyPair.Key))
	cert, err := tls.X509KeyPair(keyPair.Cert, keyPair.Key)
	//println(cert,keyPair.Cert,keyPair.Key)
	assert.NoError(t, err)
	_, err = newClient(t, 7052, &cert, ca.CertBytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
	println("002--->end")

	// Create a chaincode for example01 that tries to impersonate example02
	println("003-->")
	kp, err := auth.Generate("example01")
	assert.NoError(t, err)
	keyBytes, err := base64.StdEncoding.DecodeString(kp.Key)
	//println("AAAAA",string(keyBytes))
	assert.NoError(t, err)
	certBytes, err := base64.StdEncoding.DecodeString(kp.Cert)
	//println("BBBBB",string(certBytes))
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	mismatchedShim, err := newClient(t, 7052, &cert, ca.CertBytes()) //ca是example01,但是server是 example02  所以应该是失败的  不同的chaincode

	assert.NoError(t, err)
	defer mismatchedShim.close()
	mismatchedShim.sendMsg(registerMsg)
	mismatchedShim.sendMsg(putStateMsg)
	// Mismatched chaincode didn't get back anything
	println("accessscontrol001")
	assert.Nil(t, mismatchedShim.recv())
	println("accesscontrol0002")
	assertLogContains(t, recorder, "with given certificate hash", "belongs to a different chaincode")
	println("003-->end")

	// Create the real chaincode that its cert is generated by us that should pass the security checks
	println("-----xxxxxx------")
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	realCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer realCC.close()
	realCC.sendMsg(registerMsg)
	realCC.sendMsg(putStateMsg)
	echoMsg := realCC.recv()
	// The real chaincode should be echoed back its message
	assert.NotNil(t, echoMsg)
	assert.Equal(t, pb.ChaincodeMessage_PUT_STATE, echoMsg.Type)
	// Log should not complain about anything
	assert.Empty(t, recorder.Messages())
	println("---xxxxxx-----end-----")

	// Create the real chaincode that its cert is generated by us
	// but one that the first message sent by it isn't a register message.
	// The second message that is sent is a register message but it's "too late"
	// and the stream is already denied.
	println("004-------------------------->")
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	confusedCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer confusedCC.close()
	println("调用")
	confusedCC.sendMsg(putStateMsg)
	confusedCC.sendMsg(registerMsg)
	confusedCC.sendMsg(putStateMsg)
	assert.Nil(t, confusedCC.recv())
	println("调用完成")
	assertLogContains(t, recorder, "expected a ChaincodeMessage_REGISTER message")
	println("004---->end")

	// Create a real chaincode, that its cert was generated by us
	// but it sends a malformed first message
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	malformedMessageCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer malformedMessageCC.close()
	// Save old payload
	originalPayload := registerMsg.Payload
	registerMsg.Payload = append(registerMsg.Payload, 0)
	malformedMessageCC.sendMsg(registerMsg)
	malformedMessageCC.sendMsg(putStateMsg)
	assert.Nil(t, malformedMessageCC.recv())
	assertLogContains(t, recorder, "Failed unmarshaling message")
	// Recover old payload
	registerMsg.Payload = originalPayload

	// Create a real chaincode, that its cert was generated by us
	// but have it reconnect only after too much time.
	// This tests a use case where the CC's cert has been expired
	// and the CC has been compromised. We don't want it to be able
	// to reconnect to us.
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	lateCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer realCC.close()
	time.Sleep(ttl + time.Second*2)
	lateCC.sendMsg(registerMsg)
	lateCC.sendMsg(putStateMsg)
	echoMsg = lateCC.recv()
	assert.Nil(t, echoMsg)
	assertLogContains(t, recorder, "with given certificate hash", "not found in registry")
}

func assertLogContains(t *testing.T, r *floggingtest.Recorder, ss ...string) {
	defer r.Reset()
	for _, s := range ss {
		assert.NotEmpty(t, r.MessagesContaining(s))
	}
}
