/*
Copyright IBM Corp. 2016-2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ccpackage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/utils"
)

// ExtractSignedCCDepSpec extracts the messages from the envelope
func ExtractSignedCCDepSpec(env *common.Envelope) (*common.ChannelHeader, *peer.SignedChaincodeDeploymentSpec, error) {
	p := &common.Payload{}
	err := proto.Unmarshal(env.Payload, p)
	if err != nil {
		return nil, nil, err
	}
	if p.Header == nil {
		return nil, nil, errors.New("channel header cannot be nil")
	}
	ch := &common.ChannelHeader{}
	err = proto.Unmarshal(p.Header.ChannelHeader, ch)
	if err != nil {
		return nil, nil, err
	}

	sp := &peer.SignedChaincodeDeploymentSpec{}
	err = proto.Unmarshal(p.Data, sp)
	if err != nil {
		return nil, nil, err
	}

	println("ExtractSignedCCDepSpec", sp == nil)
	return ch, sp, nil
}

// This file provides functions for helping with the chaincode install
// package workflow. In particular
//     OwnerCreateSignedCCDepSpec - each owner creates signs the package using the same deploy
//     CreateSignedCCDepSpecForInstall - an admin or owner creates the package to be installed
//                                       using the packages from OwnerCreateSignedCCDepSpec

// ValidateCip validate the endorsed package against the base package
func ValidateCip(baseCip, otherCip *peer.SignedChaincodeDeploymentSpec) error {
	if baseCip == nil || otherCip == nil {
		panic("do not call with nil parameters")
	}

	if (baseCip.OwnerEndorsements == nil && otherCip.OwnerEndorsements != nil) || (baseCip.OwnerEndorsements != nil && otherCip.OwnerEndorsements == nil) {
		return fmt.Errorf("endorsements should either be both nil or not nil")
	}

	bN := len(baseCip.OwnerEndorsements)
	oN := len(otherCip.OwnerEndorsements)
	if bN > 1 || oN > 1 {
		return fmt.Errorf("expect utmost 1 endorsement from a owner")
	}

	if bN != oN {
		return fmt.Errorf("Rule-all packages should be endorsed or none should be endorsed failed for (%d, %d)", bN, oN)
	}

	if !bytes.Equal(baseCip.ChaincodeDeploymentSpec, otherCip.ChaincodeDeploymentSpec) {
		return fmt.Errorf("Rule-all deployment specs should match(%d, %d)", len(baseCip.ChaincodeDeploymentSpec), len(otherCip.ChaincodeDeploymentSpec))
	}

	if !bytes.Equal(baseCip.InstantiationPolicy, otherCip.InstantiationPolicy) {
		return fmt.Errorf("Rule-all instantiation policies should match(%d, %d)", len(baseCip.InstantiationPolicy), len(otherCip.InstantiationPolicy))
	}

	return nil
}

func createSignedCCDepSpec(cdsbytes []byte, instpolicybytes []byte, endorsements []*peer.Endorsement) (*common.Envelope, error) {
	if cdsbytes == nil {
		return nil, fmt.Errorf("nil chaincode deployment spec")
	}

	if instpolicybytes == nil {
		return nil, fmt.Errorf("nil instantiation policy")
	}
	println(endorsements == nil)

	// create SignedChaincodeDeploymentSpec...
	cip := &peer.SignedChaincodeDeploymentSpec{ChaincodeDeploymentSpec: cdsbytes, InstantiationPolicy: instpolicybytes, OwnerEndorsements: endorsements}

	//...and marshal it
	cipbytes := utils.MarshalOrPanic(cip)

	//use defaults (this is definitely ok for install package)
	msgVersion := int32(0)
	epoch := uint64(0)
	chdr := utils.MakeChannelHeader(common.HeaderType_CHAINCODE_PACKAGE, msgVersion, "", epoch)

	println(chdr)
	// create the payload
	payl := &common.Payload{Header: &common.Header{ChannelHeader: utils.MarshalOrPanic(chdr)}, Data: cipbytes}
	paylBytes, err := utils.GetBytesPayload(payl)
	if err != nil {
		return nil, err
	}

	// here's the unsigned  envelope. The install package is endorsed if signingEntity != nil
	return &common.Envelope{Payload: paylBytes}, nil
}

// CreateSignedCCDepSpecForInstall creates the final package from a set of packages signed by
// owners.  This is similar to how the SDK assembles a TX from various proposal
// responses from the signatures.
func CreateSignedCCDepSpecForInstall(pack []*common.Envelope) (*common.Envelope, error) {
	if len(pack) == 0 {
		return nil, errors.New("no packages provided to collate")
	}

	//rules...
	//   all packages must be endorsed or all packages should not be endorsed
	//   the chaincode deployment spec should be same
	var baseCip *peer.SignedChaincodeDeploymentSpec
	var err error
	var endorsementExists bool
	var endorsements []*peer.Endorsement
	for n, r := range pack {
		p := &common.Payload{}
		if err = proto.Unmarshal(r.Payload, p); err != nil {
			return nil, err
		}

		cip := &peer.SignedChaincodeDeploymentSpec{}
		if err = proto.Unmarshal(p.Data, cip); err != nil {
			return nil, err
		}

		//if its the first element, check if it has endorsement so we can
		//enforce endorsement rules
		if n == 0 {
			baseCip = cip
			//if it has endorsement, all other owners should have signed too
			if len(cip.OwnerEndorsements) > 0 {
				endorsements = make([]*peer.Endorsement, len(pack))
			}

		} else if err = ValidateCip(baseCip, cip); err != nil {
			return nil, err
		}

		if endorsementExists {
			endorsements[n] = cip.OwnerEndorsements[0]
		}
	}

	return createSignedCCDepSpec(baseCip.ChaincodeDeploymentSpec, baseCip.InstantiationPolicy, endorsements)
}

// OwnerCreateSignedCCDepSpec creates a package from a ChaincodeDeploymentSpec and
// optionally endorses it
func OwnerCreateSignedCCDepSpec(cds *peer.ChaincodeDeploymentSpec, instPolicy *common.SignaturePolicyEnvelope, owner msp.SigningIdentity) (*common.Envelope, error) {
	if cds == nil {
		return nil, fmt.Errorf("invalid chaincode deployment spec")
	}

	if instPolicy == nil {
		return nil, fmt.Errorf("must provide an instantiation policy")
	}

	cdsbytes := utils.MarshalOrPanic(cds)

	instpolicybytes := utils.MarshalOrPanic(instPolicy)

	var endorsements []*peer.Endorsement
	//it is not mandatory (at this utils level) to have a signature
	//this is especially convenient during dev/test
	//it may be necessary to enforce it via a policy at a higher level
	println(owner == nil)
	if owner != nil {
		println("here... ccpackage owner")
		// serialize the signing identity
		endorser, err := owner.Serialize()
		println("endorser", endorser)
		if err != nil {
			return nil, fmt.Errorf("Could not serialize the signing identity for %s, err %s", owner.GetIdentifier(), err)
		}

		// sign the concatenation of cds, instpolicy and the serialized endorser identity with this endorser's key
		signature, err := owner.Sign(append(cdsbytes, append(instpolicybytes, endorser...)...))
		println("signatire", signature)
		if err != nil {
			return nil, fmt.Errorf("Could not sign the ccpackage, err %s", err)
		}

		// each owner starts off the endorsements with one element. All such endorsed
		// packages will be collected in a final package by CreateSignedCCDepSpecForInstall
		// when endorsements will have all the entries
		endorsements = make([]*peer.Endorsement, 1)

		endorsements[0] = &peer.Endorsement{Signature: signature, Endorser: endorser}
	}

	return createSignedCCDepSpec(cdsbytes, instpolicybytes, endorsements)
}

// SignExistingPackage adds a signature to a signed package.
func SignExistingPackage(env *common.Envelope, owner msp.SigningIdentity) (*common.Envelope, error) {
	if owner == nil {
		return nil, fmt.Errorf("owner not provided")
	}

	ch, sdepspec, err := ExtractSignedCCDepSpec(env)
	println("ccpackage", err != nil)
	if err != nil {
		return nil, err
	}

	if ch == nil {
		return nil, fmt.Errorf("channel header not found in the envelope")
	}

	if sdepspec == nil || sdepspec.ChaincodeDeploymentSpec == nil || sdepspec.InstantiationPolicy == nil || sdepspec.OwnerEndorsements == nil {
		return nil, fmt.Errorf("ccpackage, 中的 -S  参数导致没有signature invalid signed deployment spec")
	}

	// serialize the signing identity
	endorser, err := owner.Serialize()
	if err != nil {
		return nil, fmt.Errorf("Could not serialize the signing identity for %s, err %s", owner.GetIdentifier(), err)
	}

	// sign the concatenation of cds, instpolicy and the serialized endorser identity with this endorser's key
	signature, err := owner.Sign(append(sdepspec.ChaincodeDeploymentSpec, append(sdepspec.InstantiationPolicy, endorser...)...))
	if err != nil {
		return nil, fmt.Errorf("Could not sign the ccpackage, err %s", err)
	}

	endorsements := append(sdepspec.OwnerEndorsements, &peer.Endorsement{Signature: signature, Endorser: endorser})

	return createSignedCCDepSpec(sdepspec.ChaincodeDeploymentSpec, sdepspec.InstantiationPolicy, endorsements)
}