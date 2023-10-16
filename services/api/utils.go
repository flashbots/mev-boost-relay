package api

import (
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	eth2builderApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilCapella "github.com/attestantio/go-eth2-client/util/capella"
	eth2UtilDeneb "github.com/attestantio/go-eth2-client/util/deneb"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/pkg/errors"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")

	ErrUnsupportedPayload = errors.New("unsupported payload version")
	ErrNoWithdrawals      = errors.New("no withdrawals")
	ErrPayloadMismatch    = errors.New("beacon-block and payload version mismatch")
	ErrHeaderHTRMismatch  = errors.New("beacon-block and payload header mismatch")
	ErrBlobMismatch       = errors.New("beacon-block and payload blob contents mismatch")
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
	withdrawals := eth2UtilCapella.ExecutionPayloadWithdrawals{Withdrawals: w}
	return withdrawals.HashTreeRoot()
}

func EqBlindedBlockContentsToBlockContents(bb *common.VersionedSignedBlindedBlockRequest, payload *builderApi.VersionedSubmitBlindedBlockResponse) error {
	if bb.Version != payload.Version {
		return errors.Wrap(ErrPayloadMismatch, fmt.Sprintf("beacon block version %d does not match payload version %d", bb.Version, payload.Version))
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{ //nolint:exhaustivestruct
		Version: payload.Version,
	}
	switch bb.Version {
	case spec.DataVersionCapella:
		bbHeaderHtr, err := bb.Capella.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Capella = payload.Capella
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Capella.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}
	case spec.DataVersionDeneb:
		block := bb.Deneb.SignedBlindedBlock.Message
		bbHeaderHtr, err := block.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Deneb.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}

		if len(bb.Deneb.SignedBlindedBlobSidecars) != len(payload.Deneb.BlobsBundle.Commitments) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG commitments")
		}
		if len(bb.Deneb.SignedBlindedBlobSidecars) != len(payload.Deneb.BlobsBundle.Proofs) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG proofs length")
		}
		if len(bb.Deneb.SignedBlindedBlobSidecars) != len(payload.Deneb.BlobsBundle.Blobs) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of blobs")
		}

		for i, blindedSidecar := range bb.Deneb.SignedBlindedBlobSidecars {
			if blindedSidecar.Message.KzgCommitment != payload.Deneb.BlobsBundle.Commitments[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG commitment at index %d", i))
			}
			if blindedSidecar.Message.KzgProof != payload.Deneb.BlobsBundle.Proofs[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG proof at index %d", i))
			}
			blobRootHelper := eth2UtilDeneb.BeaconBlockBlob{Blob: payload.Deneb.BlobsBundle.Blobs[i]}
			blobRoot, err := blobRootHelper.HashTreeRoot()
			if err != nil {
				return errors.New(fmt.Sprintf("failed to compute blob root at index %d", i))
			}
			if blindedSidecar.Message.BlobRoot != blobRoot {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched blob root at index %d", i))
			}
		}
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return ErrUnsupportedPayload
	}
	// block and payload are equal
	return nil
}

func checkBLSPublicKeyHex(pkHex string) error {
	_, err := utils.HexToPubkey(pkHex)
	return err
}

func hasReachedFork(slot, forkEpoch uint64) bool {
	currentEpoch := slot / common.SlotsPerEpoch
	return currentEpoch >= forkEpoch
}

func verifyBlockSignature(block *common.VersionedSignedBlindedBlockRequest, domain phase0.Domain, pubKey []byte) (bool, error) {
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

func verifyBlobSidecarSignature(sidecar *eth2builderApiV1Deneb.SignedBlindedBlobSidecar, domain phase0.Domain, pubKey []byte) (bool, error) {
	if sidecar == nil || sidecar.Message == nil {
		return false, errors.New("nil sidecar or message")
	}
	root, err := sidecar.Message.HashTreeRoot()
	if err != nil {
		return false, err
	}
	signingData := phase0.SigningData{ObjectRoot: root, Domain: domain}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sidecar.Signature[:], pubKey[:])
}