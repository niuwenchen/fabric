## peer中的背书服务
SignedProposal: 背书申请
ProposalResponse: 申请应答

Endorser 服务原型
    只定义了一个服务: 处理申请，参数是一个背书申请
```go
service Endorser {
	rpc ProcessProposal(SignedProposal) returns (ProposalResponse) {}
}

```
proposal.proto : 申请的定义
/*
The flow to get a generic transaction approved goes as follows:

1. client sends proposal to endorser （客户端发送请求到背书服务器）
====================================

The proposal is basically a request to do something that will result on some
action with impact on the ledger; a proposal contains a header (with some
metadata describing it, such as the type, the identity of the invoker, the
time, the ID of the chain, a cryptographic nonce..) and an opaque payload that
depends on the type specified in the header. A proposal contains the following

请求实际上是一个request，一个请求包含一个header(type,invoker,time,ID,nonce),一个不透明的payload依赖hedaer中的定义的类型。
messages:

SignedProposal （背书申请的格式）
|\_ Signature                                    (signature on the Proposal message by the creator specified in the header)
 \_ Proposal
    |\_ Header                                   (the header for this proposal)
     \_ Payload                                  (the payload for this proposal)
     
2. endorser sends proposal response back to client（背书服务器发送响应给客户端）
==================================================

The proposal response contains an endorser's response to a client's proposal. A
proposal response contains a success/error code, a response payload and a
signature (also referred to as endorsement) over the response payload. The
response payload contains a hash of the proposal (to securely link this
response to the corresponding proposal) and an opaque extension field that
depends on the type specified in the header of the corresponding proposal. A
proposal response contains the following messages:

申请应答 给客户端的申请+背书响应； 一个背书响应包含一个success/error code,一个响应payload和一个签名(作为背书服务的参考)。response payload包含一个申请的hash值(安全的讲这个响应和对应的请求)和一个不透明的值

ProposalResponse
|\_ Endorsement                                  (the endorser's signature over the whole response payload)
 \_ ProposalResponsePayload                      (the payload of the proposal response)

3. client assembles endorsements into a transaction （客户端把这个endorsment嵌入一个交易中）
===================================================

A transaction message assembles one or more proposals and corresponding
responses into a message to be sent to orderers. After ordering, (batches of)
transactions are delivered to committing peers for validation and final
delivery into the ledger. A transaction contains one or more actions. Each of
them contains a header (same as that of the proposal that requested it) and an
opaque payload that depends on the type specified in the header.

一个交易信息中包含一个或多个请求和对应的应答信息 发送到orders；经过排序后，多个交易被传输到committer peers，去验证然后最后投递到ledger(账本)； 一个交易包含多个行为
每一个包含一个header(和请求一样)，和一个不透明的payload 依赖于特殊的hedaer

SignedTransaction
|\_ Signature                                    (signature on the Transaction message by the creator specified in the header)
 \_ Transaction
     \_ TransactionAction (1...n)
        |\_ Header (1)                           (the header of the proposal that requested this action)
         \_ Payload (1)                          (the payload for this action)
*/





message Proposal {

	// The header of the proposal. It is the bytes of the Header
bytes header = 1;

	// The payload of the proposal as defined by the type in the proposal
	// header.
bytes payload = 2;

	// Optional extensions to the proposal. Its content depends on the Header's
	// type field.  For the type CHAINCODE, it might be the bytes of a
	// ChaincodeAction message.
bytes extension = 3;
}






message SignedProposal {

	// The bytes of Proposal
bytes proposal_bytes = 1;

  // Signaure over proposalBytes; this signature is to be verified against
  // the creator identity contained in the header of the Proposal message
  // marshaled as proposalBytes
	bytes signature = 2;
}


数据结构分析完毕，里面还有些细节，暂不深究

## 代码方面
在peer的node中进行了使用

###11 endorser
```go
endorserSupport := &endorser.SupportImpl{
		SignerSupport:    signingIdentity,
		Peer:             peer.Default,
		PeerSupport:      peer.DefaultSupport,
		ChaincodeSupport: chaincodeSupport,
		SysCCProvider:    sccp,
		ACLProvider:      aclProvider,
	}
	endorsementPluginsByName := reg.Lookup(library.Endorsement).(map[string]endorsement2.PluginFactory)
	validationPluginsByName := reg.Lookup(library.Validation).(map[string]validation.PluginFactory)
	signingIdentityFetcher := (endorsement3.SigningIdentityFetcher)(endorserSupport)
	channelStateRetriever := endorser.ChannelStateRetriever(endorserSupport)
	pluginMapper := endorser.MapBasedPluginMapper(endorsementPluginsByName)
	pluginEndorser := endorser.NewPluginEndorser(&endorser.PluginSupport{
		ChannelStateRetriever:   channelStateRetriever,
		TransientStoreRetriever: peer.TransientStoreFactory,
		PluginMapper:            pluginMapper,
		SigningIdentityFetcher:  signingIdentityFetcher,
	})
	endorserSupport.PluginEndorser = pluginEndorser

	serverEndorser := endorser.NewEndorserServer(privDataDist, endorserSupport, pr)

```

endorser.go
```go

type privateDataDistributor func(channel string, txID string, privateData *transientstore.TxPvtReadWriteSetWithConfigInfo, blkHt uint64) error
// 参数: channel transactionId, privateDara(事务数据)

// Support contains functions that the endorser requires to execute its tasks
type Support interface {
	crypto.SignerSupport
	// IsSysCCAndNotInvokableExternal returns true if the supplied chaincode is
	// ia system chaincode and it NOT invokable
	IsSysCCAndNotInvokableExternal(name string) bool // 验证提供的chaincode是否 系统chaincode 并且不是invokable

	// GetTxSimulator returns the transaction simulator for the specified ledger
	// a client may obtain more than one such simulator; they are made unique
	// by way of the supplied txid
	GetTxSimulator(ledgername string, txid string) (ledger.TxSimulator, error) // 返回交易simulator给特定的ledger

	// GetHistoryQueryExecutor gives handle to a history query executor for the
	// specified ledger
	GetHistoryQueryExecutor(ledgername string) (ledger.HistoryQueryExecutor, error)  // 返回历史查询

	// GetTransactionByID retrieves a transaction by id
	GetTransactionByID(chid, txID string) (*pb.ProcessedTransaction, error) // 根据交易id返回一个transaction

	// IsSysCC returns true if the name matches a system chaincode's
	// system chaincode names are system, chain wide
	IsSysCC(name string) bool //判断是否是 系统chaincode

	// Execute - execute proposal, return original response of chaincode  // 执行请求，返回原始的chaincode的响应
	Execute(txParams *ccprovider.TransactionParams, cid, name, version, txid string, signedProp *pb.SignedProposal, prop *pb.Proposal, input *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error)

	// ExecuteLegacyInit - executes a deployment proposal, return original response of chaincode  // 执行一个部署的请求，返回原始的chaincode响应
	ExecuteLegacyInit(txParams *ccprovider.TransactionParams, cid, name, version, txid string, signedProp *pb.SignedProposal, prop *pb.Proposal, spec *pb.ChaincodeDeploymentSpec) (*pb.Response, *pb.ChaincodeEvent, error)

	// GetChaincodeDefinition returns ccprovider.ChaincodeDefinition for the chaincode with the supplied name // 返回ccprovider.ChaincodeDefination
	GetChaincodeDefinition(chaincodeID string, txsim ledger.QueryExecutor) (ccprovider.ChaincodeDefinition, error)

	// CheckACL checks the ACL for the resource for the channel using the
	// SignedProposal from which an id can be extracted for testing against a policy  // 检查ACL 使用背书申请
	CheckACL(signedProp *pb.SignedProposal, chdr *common.ChannelHeader, shdr *common.SignatureHeader, hdrext *pb.ChaincodeHeaderExtension) error

	// IsJavaCC returns true if the CDS package bytes describe a chaincode
	// that requires the java runtime environment to execute
	IsJavaCC(buf []byte) (bool, error)  // 判断是否是Java Chaincode

	// CheckInstantiationPolicy returns an error if the instantiation in the supplied
	// ChaincodeDefinition differs from the instantiation policy stored on the ledger
	CheckInstantiationPolicy(name, version string, cd ccprovider.ChaincodeDefinition) error // 检查实例化的chaincode

	// GetChaincodeDeploymentSpecFS returns the deploymentspec for a chaincode from the fs
	GetChaincodeDeploymentSpecFS(cds *pb.ChaincodeDeploymentSpec) (*pb.ChaincodeDeploymentSpec, error)

	// GetApplicationConfig returns the configtxapplication.SharedConfig for the Channel
	// and whether the Application config exists
	GetApplicationConfig(cid string) (channelconfig.Application, bool)

	// NewQueryCreator creates a new QueryCreator
	NewQueryCreator(channel string) (QueryCreator, error)

	// EndorseWithPlugin endorses the response with a plugin
	EndorseWithPlugin(ctx Context) (*pb.ProposalResponse, error)

	// GetLedgerHeight returns ledger height for given channelID
	GetLedgerHeight(channelID string) (uint64, error)
}



// Endorser provides the Endorser service ProcessProposal
type Endorser struct {
	distributePrivateData privateDataDistributor
	s                     Support
	PlatformRegistry      *platforms.Registry   // 这个不清楚
	PvtRWSetAssembler
}


// NewEndorserServer creates and returns a new Endorser server instance.
func NewEndorserServer(privDist privateDataDistributor, s Support, pr *platforms.Registry) *Endorser {
	e := &Endorser{
		distributePrivateData: privDist,
		s:                 s,
		PlatformRegistry:  pr,
		PvtRWSetAssembler: &rwSetAssembler{},
	}
	return e
}


// call specified chaincode (system or user)
func (e *Endorser) callChaincode(txParams *ccprovider.TransactionParams, version string, input *pb.ChaincodeInput, cid *pb.ChaincodeID) (*pb.Response, *pb.ChaincodeEvent, error) {
	
}
```


### processProposal
```go
// ProcessProposal process the Proposal
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error) {
	addr := util.ExtractRemoteAddress(ctx)
	endorserLogger.Debug("Entering: request from", addr)
	defer endorserLogger.Debug("Exit: request from", addr)

	// 0 -- check and validate
	vr, err := e.preProcess(signedProp)
	if err != nil {
		resp := vr.resp
		return resp, err
	}

	prop, hdrExt, chainID, txid := vr.prop, vr.hdrExt, vr.chainID, vr.txid

	// obtaining once the tx simulator for this proposal. This will be nil
	// for chainless proposals
	// Also obtain a history query executor for history queries, since tx simulator does not cover history
	var txsim ledger.TxSimulator
	var historyQueryExecutor ledger.HistoryQueryExecutor
	if acquireTxSimulator(chainID, vr.hdrExt.ChaincodeId) {
		if txsim, err = e.s.GetTxSimulator(chainID, txid); err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
		}

		// txsim acquires a shared lock on the stateDB. As this would impact the block commits (i.e., commit
		// of valid write-sets to the stateDB), we must release the lock as early as possible.
		// Hence, this txsim object is closed in simulateProposal() as soon as the tx is simulated and
		// rwset is collected before gossip dissemination if required for privateData. For safety, we
		// add the following defer statement and is useful when an error occur. Note that calling
		// txsim.Done() more than once does not cause any issue. If the txsim is already
		// released, the following txsim.Done() simply returns.
		defer txsim.Done()

		if historyQueryExecutor, err = e.s.GetHistoryQueryExecutor(chainID); err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
		}
	}

	txParams := &ccprovider.TransactionParams{
		ChannelID:            chainID,
		TxID:                 txid,
		SignedProp:           signedProp,
		Proposal:             prop,
		TXSimulator:          txsim,
		HistoryQueryExecutor: historyQueryExecutor,
	}
	// this could be a request to a chainless SysCC

	// TODO: if the proposal has an extension, it will be of type ChaincodeAction;
	//       if it's present it means that no simulation is to be performed because
	//       we're trying to emulate a submitting peer. On the other hand, we need
	//       to validate the supplied action before endorsing it

	// 1 -- simulate
	cd, res, simulationResult, ccevent, err := e.SimulateProposal(txParams, hdrExt.ChaincodeId)
	if err != nil {
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
	}
	if res != nil {
		if res.Status >= shim.ERROR {
			endorserLogger.Errorf("[%s][%s] simulateProposal() resulted in chaincode %s response status %d for txid: %s", chainID, shorttxid(txid), hdrExt.ChaincodeId, res.Status, txid)
			var cceventBytes []byte
			if ccevent != nil {
				cceventBytes, err = putils.GetBytesChaincodeEvent(ccevent)
				if err != nil {
					return nil, errors.Wrap(err, "failed to marshal event bytes")
				}
			}
			pResp, err := putils.CreateProposalResponseFailure(prop.Header, prop.Payload, res, simulationResult, cceventBytes, hdrExt.ChaincodeId, hdrExt.PayloadVisibility)
			if err != nil {
				return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
			}

			return pResp, nil
		}
	}

	// 2 -- endorse and get a marshalled ProposalResponse message
	var pResp *pb.ProposalResponse

	// TODO till we implement global ESCC, CSCC for system chaincodes
	// chainless proposals (such as CSCC) don't have to be endorsed
	if chainID == "" {
		pResp = &pb.ProposalResponse{Response: res}
	} else {
		//Note: To endorseProposal(), we pass the released txsim. Hence, an error would occur if we try to use this txsim
		pResp, err = e.endorseProposal(ctx, chainID, txid, signedProp, prop, res, simulationResult, ccevent, hdrExt.PayloadVisibility, hdrExt.ChaincodeId, txsim, cd)
		if err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
		}
		if pResp.Response.Status >= shim.ERRORTHRESHOLD {
			endorserLogger.Debugf("[%s][%s] endorseProposal() resulted in chaincode %s error for txid: %s", chainID, shorttxid(txid), hdrExt.ChaincodeId, txid)
			return pResp, nil
		}
	}

	// Set the proposal response payload - it
	// contains the "return value" from the
	// chaincode invocation
	pResp.Response = res

	return pResp, nil
}

```
0: check and validate
```go
    vr := &validateResult{}
	// at first, we check whether the message is valid 
	prop, hdr, hdrExt, err := validation.ValidateProposalMessage(signedProp)
    
	prop, err := utils.GetProposal(signedProp.ProposalBytes) //---->就是peer.Proposal 的类型
	// GetProposal returns a Proposal message from its bytes
    func GetProposal(propBytes []byte) (*peer.Proposal, error) {
    	prop := &peer.Proposal{}
    	err := proto.Unmarshal(propBytes, prop)
    	return prop, errors.Wrap(err, "error unmarshaling Proposal")
    }
	
	// 1) look at the ProposalHeader
	hdr, err := utils.GetHeader(prop.Header)
	// GetHeader Get Header from bytes
    func GetHeader(bytes []byte) (*common.Header, error) {
    	hdr := &common.Header{}    //这里只是构造一个结构体，并没有从proposal中获取数据
    	err := proto.Unmarshal(bytes, hdr)
    	return hdr, errors.Wrap(err, "error unmarshaling Header")
    }
	
	
	// validate the header
	chdr, shdr, err := validateCommonHeader(hdr)
	if err != nil {
		return nil, nil, nil, err
	}


	// validate the signature
	err = checkSignatureFromCreator(shdr.Creator, signedProp.Signature, signedProp.ProposalBytes, chdr.ChannelId)
	
	// Verify that the transaction ID has been computed properly.
	// This check is needed to ensure that the lookup into the ledger
	// for the same TxID catches duplicates. 
	err = utils.CheckProposalTxID(chdr.TxId, shdr.Nonce, shdr.Creator)
    	
    
	// validation of the proposal message knowing it's of type CHAINCODE
	chaincodeHdrExt, err := validateChaincodeProposalMessage(prop, hdr)
	if err != nil {
		return nil, nil, nil, err
	}
    
	return prop, hdr, chaincodeHdrExt, err
    
  
```

验证消息之后，
```go
chdr, err := putils.UnmarshalChannelHeader(hdr.ChannelHeader)
	if err != nil {
		vr.resp = &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}
		return vr, err
	}

	shdr, err := putils.GetSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		vr.resp = &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}
		return vr, err
	}
	
	//再次使用putils的函数获取Header的ChannelHeader和SignatureHeader,分别为chdr和shdr，然后使用函数IsSysCCAndNotInvokableExternal
	//验证目前处理的SignedProposal 涉及的chaincode的ID是否是系统chaincode。 若是，验证是否能被外部调用
	// 如果该chaincode是系统chaincode 但不能被外部调用，返回true，进入if分支，返回相应错误
	// 
```

第三步: ValidatePropsolMessage的检查中并没有检查频道ID,当拼单ID不为空时，程序根据频道ID调用GetLeager获取peer本地的PeerLedger,然后根据交易ID调用账本对象自身函数，查看该交易是否是
已经存在于账本中，即交易的唯一性检查。
接下来进行策略检查，当chaincode不是系统chaincode时，会调用背书者成员policyChekcer的函数checkACL，对背书者接收到的SignedProposal是否符合频道的写者策略(writers policy of the chain)进行
检查(系统chaincode的检查在其他地方)。
如果频道ID为空，则什么都不做，因为交易忽略了唯一性检查，没有频道ID的proposal不会影响ledger，也不会被提交，没有频道ID的proposal是对照peer本地的MSP验证有效的，不是通过ValidateProposalMessage函数
来验证proposal的有效性。

```go
if chainID != "" {
		// Here we handle uniqueness check and ACLs for proposals targeting a chain
		// Notice that ValidateProposalMessage has already verified that TxID is computed properly
		if _, err = e.s.GetTransactionByID(chainID, txid); err == nil {
			err = errors.Errorf("duplicate transaction found [%s]. Creator [%x]", txid, shdr.Creator)
			vr.resp = &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}
			return vr, err
		}

		// check ACL only for application chaincodes; ACLs
		// for system chaincodes are checked elsewhere
		if !e.s.IsSysCC(hdrExt.ChaincodeId.Name) {
			// check that the proposal complies with the Channel's writers
			if err = e.s.CheckACL(signedProp, chdr, shdr, hdrExt); err != nil {
				vr.resp = &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}
				return vr, err
			}
		}
	} else {
		// chainless proposals do not/cannot affect ledger and cannot be submitted as transactions
		// ignore uniqueness checks; also, chainless proposals are not validated using the policies
		// of the chain since by definition there is no chain; they are validated against the local
		// MSP of the peer instead by the call to ValidateProposalMessage above
	}

	vr.prop, vr.hdrExt, vr.chainID, vr.txid = prop, hdrExt, chainID, txid
	return vr, nil
	
```

第四步：
当频道ID不为空时，背书对象使用自身函数 GetTxSumulator 和 GetHistoryQueryExecutor,根据频道ID分别获取了交易模拟对象和账本历史查询对象进行模拟(simulate)交易。从这里可以看出，频道
ID也被作为了这个频道的账本的名称。因为peer的账本存在于/fabric/core/peer/peer.go 的chains映射中的，映射的key就是频道ID
 ```go

    var txsim ledger.TxSimulator
	var historyQueryExecutor ledger.HistoryQueryExecutor
	if acquireTxSimulator(chainID, vr.hdrExt.ChaincodeId) {
		if txsim, err = e.s.GetTxSimulator(chainID, txid); err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
		}

		// txsim acquires a shared lock on the stateDB. As this would impact the block commits (i.e., commit
		// of valid write-sets to the stateDB), we must release the lock as early as possible.
		// Hence, this txsim object is closed in simulateProposal() as soon as the tx is simulated and
		// rwset is collected before gossip dissemination if required for privateData. For safety, we
		// add the following defer statement and is useful when an error occur. Note that calling
		// txsim.Done() more than once does not cause any issue. If the txsim is already
		// released, the following txsim.Done() simply returns.
		defer txsim.Done()

		if historyQueryExecutor, err = e.s.GetHistoryQueryExecutor(chainID); err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
		}
	}


txParams := &ccprovider.TransactionParams{
		ChannelID:            chainID,
		TxID:                 txid,
		SignedProp:           signedProp,
		Proposal:             prop,
		TXSimulator:          txsim,
		HistoryQueryExecutor: historyQueryExecutor,
	}

// 1 -- simulate
cd, res, simulationResult, ccevent, err := e.SimulateProposal(txParams, hdrExt.ChaincodeId)
	

```

