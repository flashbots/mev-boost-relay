package api

import (
	"errors"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	boostTypes "github.com/flashbots/go-boost-utils/types"
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

func SanityCheckBuilderBlockSubmission(payload *common.BuilderSubmitBlockRequest) error {
	if payload.BlockHash() != payload.ExecutionPayloadBlockHash() {
		return ErrBlockHashMismatch
	}

	if payload.ParentHash() != payload.ExecutionPayloadParentHash() {
		return ErrParentHashMismatch
	}

	return nil
}

func checkBLSPublicKeyHex(pkHex string) error {
	var proposerPubkey boostTypes.PublicKey
	return proposerPubkey.UnmarshalText([]byte(pkHex))
}

func ComputeWithdrawalsRoot(w []*capella.Withdrawal) (phase0.Root, error) {
	if w == nil {
		return phase0.Root{}, ErrNoWithdrawals
	}
	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: w}
	return withdrawals.HashTreeRoot()
}

func EqExecutionPayloadToHeader(bb *common.SignedBlindedBeaconBlock, payload *common.VersionedExecutionPayload) error {
	if bb.Bellatrix != nil { // process Bellatrix beacon block
		if payload.Bellatrix == nil {
			return ErrPayloadMismatchBellatrix
		}
		bbHeaderHtr, err := bb.Bellatrix.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		payloadHeader, err := boostTypes.PayloadToPayloadHeader(payload.Bellatrix.Data)
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

		// bellatrix block and payload are equal
		return nil
	}

	if bb.Capella != nil { // process Capella beacon block
		if payload.Capella == nil {
			return ErrPayloadMismatchCapella
		}

		bbHeaderHtr, err := bb.Capella.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		payloadHeader, err := common.CapellaPayloadToPayloadHeader(payload.Capella.Capella)
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
