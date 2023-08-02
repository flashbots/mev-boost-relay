package api

import (
	"errors"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")

	ErrNoPayloads               = errors.New("no payloads")
	ErrNoWithdrawals            = errors.New("no withdrawals")
	ErrPayloadMismatchBellatrix = errors.New("bellatrix beacon-block but no bellatrix payload")
	ErrPayloadMismatchCapella   = errors.New("capella beacon-block but no capella payload")
	ErrHeaderHTRMismatch        = errors.New("beacon-block and payload header mismatch")
)

func SanityCheckBuilderBlockSubmission(payload *common.VersionedSubmitBlockRequest) error {
	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		return err
	}
	if submission.BlockHash.String() != submission.ExecutionPayloadBlockHash.String() {
		return ErrBlockHashMismatch
	}

	if submission.ParentHash.String() != submission.ExecutionPayloadParentHash.String() {
		return ErrParentHashMismatch
	}

	return nil
}

func ComputeWithdrawalsRoot(w []*capella.Withdrawal) (phase0.Root, error) {
	if w == nil {
		return phase0.Root{}, ErrNoWithdrawals
	}
	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: w}
	return withdrawals.HashTreeRoot()
}

func EqExecutionPayloadToHeader(bb *common.VersionedSignedBlindedBlockRequest, payload *api.VersionedExecutionPayload) error {
	if bb.Capella != nil { // process Capella beacon block
		if payload.Capella == nil {
			return ErrPayloadMismatchCapella
		}

		bbHeaderHtr, err := bb.Capella.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		payloadHeader, err := common.CapellaPayloadToPayloadHeader(payload.Capella)
		if err != nil {
			return err
		}
		payloadHeaderHtr, err := payloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}

		// capella block and payload are equal
		return nil
	}

	return ErrNoPayloads
}

func checkBLSPublicKeyHex(pkHex string) error {
	_, err := utils.HexToPubkey(pkHex)
	return err
}

func hasReachedFork(slot, forkEpoch uint64) bool {
	currentEpoch := slot / common.SlotsPerEpoch
	return currentEpoch >= forkEpoch
}

func checkProposerSignature(block *common.VersionedSignedBlindedBlockRequest, domain phase0.Domain, pubKey []byte) (bool, error) {
	root, err := block.Root()
	if err != nil {
		return false, err
	}
	sig, err := block.BeaconBlockSignature()
	if err != nil {
		return false, err
	}
	signingData := phase0.SigningData{ObjectRoot: root, Domain: domain}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sig[:], pubKey[:])
}
