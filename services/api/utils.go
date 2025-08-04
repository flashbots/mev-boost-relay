package api

import (
	"encoding/binary"
	"fmt"
	"mime"
	"net/http"

	builderApi "github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilCapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")

	ErrUnsupportedPayload   = errors.New("unsupported payload version")
	ErrNoWithdrawals        = errors.New("no withdrawals")
	ErrNoDepositRequests    = errors.New("no deposit receipts")
	ErrNoWithdrawalRequests = errors.New("no execution layer withdrawal requests")
	ErrPayloadMismatch      = errors.New("beacon-block and payload version mismatch")
	ErrHeaderHTRMismatch    = errors.New("beacon-block and payload header mismatch")
	ErrBlobMismatch         = errors.New("beacon-block and payload blob contents mismatch")
	ErrNotAcceptable        = errors.New("not acceptable")
)

func SanityCheckBuilderBlockSubmission(payload *common.VersionedSubmitBlockRequest) error {
	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		return err
	}
	if submission.BidTrace.BlockHash.String() != submission.ExecutionPayloadBlockHash.String() {
		return ErrBlockHashMismatch
	}

	if submission.BidTrace.ParentHash.String() != submission.ExecutionPayloadParentHash.String() {
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

func EqBlindedBlockContentsToBlockContents(bb *common.VersionedSignedBlindedBeaconBlock, payload *builderApi.VersionedSubmitBlindedBlockResponse) error {
	if bb.Version != payload.Version {
		return errors.Wrap(ErrPayloadMismatch, fmt.Sprintf("beacon block version %d does not match payload version %d", bb.Version, payload.Version))
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{ //nolint:exhaustivestruct
		Version: payload.Version,
	}
	switch bb.Version { //nolint:exhaustive
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
		block := bb.Deneb.Message
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

		if len(bb.Deneb.Message.Body.BlobKZGCommitments) != len(payload.Deneb.BlobsBundle.Commitments) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG commitments")
		}

		for i, commitment := range bb.Deneb.Message.Body.BlobKZGCommitments {
			if commitment != payload.Deneb.BlobsBundle.Commitments[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG commitment at index %d", i))
			}
		}
	case spec.DataVersionElectra:
		block := bb.Electra.Message
		bbHeaderHtr, err := block.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Electra = payload.Electra.ExecutionPayload
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Electra.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}

		if len(bb.Electra.Message.Body.BlobKZGCommitments) != len(payload.Electra.BlobsBundle.Commitments) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG commitments")
		}

		for i, commitment := range bb.Electra.Message.Body.BlobKZGCommitments {
			if commitment != payload.Electra.BlobsBundle.Commitments[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG commitment at index %d", i))
			}
		}

	case spec.DataVersionFulu:
		block := bb.Fulu.Message
		bbHeaderHtr, err := block.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Fulu = payload.Fulu.ExecutionPayload
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Fulu.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}

		if len(bb.Fulu.Message.Body.BlobKZGCommitments) != len(payload.Fulu.BlobsBundle.Commitments) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG commitments")
		}

		for i, commitment := range bb.Fulu.Message.Body.BlobKZGCommitments {
			if commitment != payload.Fulu.BlobsBundle.Commitments[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG commitment at index %d", i))
			}
		}

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

func hasReachedFork(slot uint64, forkEpoch int64) bool {
	if forkEpoch < 0 {
		return false
	}
	currentEpoch := slot / common.SlotsPerEpoch
	return currentEpoch >= uint64(forkEpoch)
}

func verifyBlockSignature(block *common.VersionedSignedBlindedBeaconBlock, domain phase0.Domain, pubKey []byte) (bool, error) {
	root, err := block.Root()
	if err != nil {
		return false, err
	}
	sig, err := block.Signature()
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

func getPayloadAttributesKey(parentHash string, slot uint64) string {
	return fmt.Sprintf("%s-%d", parentHash, slot)
}

// getHeaderContentType parses the Content-Type header and returns the media type and parameters.
// It returns an empty mediaType string and nil parameters if the header is not set or empty.
func getHeaderContentType(header http.Header) (mediatype string, params map[string]string, err error) {
	contentType := header.Get(HeaderContentType)
	if contentType == "" {
		return "", nil, nil
	}

	// Parse the content type
	contentType, params, err = mime.ParseMediaType(contentType)
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to parse Content-Type header")
	}

	return contentType, params, nil
}

func getSlotFromBuilderJSONPayload(input []byte) (uint64, error) {
	slot := gjson.Get(string(input), "message.slot")
	if !slot.Exists() {
		return 0, fmt.Errorf("slot not found in payload")
	}
	return slot.Uint(), nil
}

func getSlotFromBuilderSSZPayload(input []byte) (uint64, error) {
	if len(input) < 4 {
		return 0, fmt.Errorf("payload too short to contain message offset")
	}

	messageOffset := binary.LittleEndian.Uint32(input[4:8])

	slot := binary.LittleEndian.Uint64(input[messageOffset : messageOffset+8])

	return slot, nil
}
