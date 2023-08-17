package common

import (
	"encoding/json"
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilDeneb "github.com/attestantio/go-eth2-client/util/deneb"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/pkg/errors"
)

var (
	ErrMissingRequest     = errors.New("req is nil")
	ErrMissingSecretKey   = errors.New("secret key is nil")
	ErrInvalidTransaction = errors.New("invalid transaction")
	ErrInvalidVersion     = errors.New("invalid version")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var ZeroU256 = boostTypes.IntToU256(0)

func BuildGetHeaderResponse(payload *VersionedSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{Version: payload.Version}
	switch payload.Version {
	case spec.DataVersionCapella:
		versionedPayload.Capella = payload.Capella.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionCapella,
			Capella: signedBuilderBid.Capella,
		}, nil
	case spec.DataVersionDeneb:
		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb:   signedBuilderBid.Deneb,
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, ErrInvalidVersion
	default:
		return nil, ErrEmptyPayload
	}
}

func BuildGetPayloadResponse(payload *VersionedSubmitBlockRequest) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	switch payload.Version {
	case spec.DataVersionCapella:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionCapella,
			Capella: payload.Capella.ExecutionPayload,
		}, nil
	case spec.DataVersionDeneb:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: payload.Deneb.ExecutionPayload,
				BlobsBundle:      payload.Deneb.BlobsBundle,
			},
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, ErrInvalidVersion
	}
	return nil, ErrEmptyPayload
}

func BuilderBlockRequestToSignedBuilderBid(payload *VersionedSubmitBlockRequest, header *builderApi.VersionedExecutionPayloadHeader, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	value, err := payload.Value()
	if err != nil {
		return nil, err
	}

	switch payload.Version {
	case spec.DataVersionCapella:
		builderBid := builderApiCapella.BuilderBid{
			Value:  value,
			Header: header.Capella,
			Pubkey: *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionCapella,
			Capella: &builderApiCapella.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case spec.DataVersionDeneb:
		var blobRoots []phase0.Root
		for i, blob := range payload.Deneb.BlobsBundle.Blobs {
			blobRootHelper := eth2UtilDeneb.BeaconBlockBlob{Blob: blob}
			root, err := blobRootHelper.HashTreeRoot()
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to calculate blob root at blob index %d", i))
			}
			blobRoots = append(blobRoots, root)
		}
		blindedBlobRoots := builderApiDeneb.BlindedBlobsBundle{
			Commitments: payload.Deneb.BlobsBundle.Commitments,
			Proofs:      payload.Deneb.BlobsBundle.Proofs,
			BlobRoots:   blobRoots,
		}

		builderBid := builderApiDeneb.BuilderBid{
			Value:              value,
			Header:             header.Deneb,
			BlindedBlobsBundle: &blindedBlobRoots,
			Pubkey:             *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version.String()))
	}
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *VersionedSignedBlindedBlockRequest, blockPayload *builderApi.VersionedSubmitBlindedBlockResponse) (*VersionedSignedBlockRequest, error) {
	signedBeaconBlock := VersionedSignedBlockRequest{
		eth2Api.VersionedBlockRequest{ //nolint:exhaustruct
			Version: signedBlindedBeaconBlock.Version,
		},
	}
	switch signedBlindedBeaconBlock.Version {
	case spec.DataVersionCapella:
		capellaBlindedBlock := signedBlindedBeaconBlock.Capella
		signedBeaconBlock.Capella = CapellaUnblindSignedBlock(capellaBlindedBlock, blockPayload.Capella)
	case spec.DataVersionDeneb:
		denebBlindedBlock := signedBlindedBeaconBlock.Deneb.SignedBlindedBlock
		blockRoot, err := denebBlindedBlock.Message.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		signedBeaconBlock.Deneb = DenebUnblindSignedBlock(denebBlindedBlock, blockPayload.Deneb, blockRoot)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", signedBlindedBeaconBlock.Version.String()))
	}
	return &signedBeaconBlock, nil
}

func CapellaUnblindSignedBlock(blindedBlock *eth2ApiV1Capella.SignedBlindedBeaconBlock, executionPayload *capella.ExecutionPayload) *capella.SignedBeaconBlock {
	return &capella.SignedBeaconBlock{
		Signature: blindedBlock.Signature,
		Message: &capella.BeaconBlock{
			Slot:          blindedBlock.Message.Slot,
			ProposerIndex: blindedBlock.Message.ProposerIndex,
			ParentRoot:    blindedBlock.Message.ParentRoot,
			StateRoot:     blindedBlock.Message.StateRoot,
			Body: &capella.BeaconBlockBody{
				BLSToExecutionChanges: blindedBlock.Message.Body.BLSToExecutionChanges,
				RANDAOReveal:          blindedBlock.Message.Body.RANDAOReveal,
				ETH1Data:              blindedBlock.Message.Body.ETH1Data,
				Graffiti:              blindedBlock.Message.Body.Graffiti,
				ProposerSlashings:     blindedBlock.Message.Body.ProposerSlashings,
				AttesterSlashings:     blindedBlock.Message.Body.AttesterSlashings,
				Attestations:          blindedBlock.Message.Body.Attestations,
				Deposits:              blindedBlock.Message.Body.Deposits,
				VoluntaryExits:        blindedBlock.Message.Body.VoluntaryExits,
				SyncAggregate:         blindedBlock.Message.Body.SyncAggregate,
				ExecutionPayload:      executionPayload,
			},
		},
	}
}

func DenebUnblindSignedBlock(blindedBlock *eth2ApiV1Deneb.SignedBlindedBeaconBlock, blockPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle, blockRoot phase0.Root) *eth2ApiV1Deneb.SignedBlockContents {
	denebBlobSidecars := make([]*deneb.SignedBlobSidecar, len(blockPayload.BlobsBundle.Blobs))

	for i := range denebBlobSidecars {
		denebBlobSidecars[i] = &deneb.SignedBlobSidecar{
			Message: &deneb.BlobSidecar{
				BlockRoot:       blockRoot,
				Index:           deneb.BlobIndex(i),
				Slot:            blindedBlock.Message.Slot,
				BlockParentRoot: blindedBlock.Message.ParentRoot,
				ProposerIndex:   blindedBlock.Message.ProposerIndex,
				Blob:            blockPayload.BlobsBundle.Blobs[i],
				KzgCommitment:   blockPayload.BlobsBundle.Commitments[i],
				KzgProof:        blockPayload.BlobsBundle.Proofs[i],
			},
			Signature: denebBlobSidecars[i].Signature,
		}
	}
	return &eth2ApiV1Deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message: &deneb.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &deneb.BeaconBlockBody{
					BLSToExecutionChanges: blindedBlock.Message.Body.BLSToExecutionChanges,
					RANDAOReveal:          blindedBlock.Message.Body.RANDAOReveal,
					ETH1Data:              blindedBlock.Message.Body.ETH1Data,
					Graffiti:              blindedBlock.Message.Body.Graffiti,
					ProposerSlashings:     blindedBlock.Message.Body.ProposerSlashings,
					AttesterSlashings:     blindedBlock.Message.Body.AttesterSlashings,
					Attestations:          blindedBlock.Message.Body.Attestations,
					Deposits:              blindedBlock.Message.Body.Deposits,
					VoluntaryExits:        blindedBlock.Message.Body.VoluntaryExits,
					SyncAggregate:         blindedBlock.Message.Body.SyncAggregate,
					ExecutionPayload:      blockPayload.ExecutionPayload,
					BlobKzgCommitments:    blockPayload.BlobsBundle.Commitments,
				},
			},
			Signature: blindedBlock.Signature,
		},
		SignedBlobSidecars: denebBlobSidecars,
	}
}

type BuilderBlockValidationRequest struct {
	VersionedSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequest) MarshalJSON() ([]byte, error) {
	blockRequest, err := json.Marshal(r.VersionedSubmitBlockRequest)
	if err != nil {
		return nil, err
	}
	gasLimit, err := json.Marshal(&struct {
		RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
	}{
		RegisteredGasLimit: r.RegisteredGasLimit,
	})
	if err != nil {
		return nil, err
	}
	gasLimit[0] = ','
	return append(blockRequest[:len(blockRequest)-1], gasLimit...), nil
}

type VersionedSubmitBlockRequest struct {
	builderSpec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZ(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(builderApiCapella.SubmitBlockRequest)
	if err = capellaRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = json.Unmarshal(input, denebRequest); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(builderApiCapella.SubmitBlockRequest)
	if err = json.Unmarshal(input, capellaRequest); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest")
}

type VersionedSignedBlockRequest struct {
	eth2Api.VersionedBlockRequest
}

func (r *VersionedSignedBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSignedBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	denebContents := new(eth2ApiV1Deneb.SignedBlockContents)
	if err = json.Unmarshal(input, denebContents); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebContents
		return nil
	}

	capellaBlock := new(capella.SignedBeaconBlock)
	if err = json.Unmarshal(input, capellaBlock); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaBlock
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SignedBeaconBlockRequest")
}

type VersionedSignedBlindedBlockRequest struct {
	eth2Api.VersionedBlindedBlockRequest
}

func (r *VersionedSignedBlindedBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSignedBlindedBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	denebContents := new(eth2ApiV1Deneb.SignedBlindedBlockContents)
	if err = json.Unmarshal(input, denebContents); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebContents
		return nil
	}

	capellaBlock := new(eth2ApiV1Capella.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, capellaBlock); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaBlock
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SignedBlindedBeaconBlock")
}
