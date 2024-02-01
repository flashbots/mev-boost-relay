package common

import (
	"encoding/json"
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/pkg/errors"
)

var (
	ErrMissingRequest   = errors.New("req is nil")
	ErrMissingSecretKey = errors.New("secret key is nil")
	ErrInvalidVersion   = errors.New("invalid version")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

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

	switch payload.Version { //nolint:exhaustive
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
		builderBid := builderApiDeneb.BuilderBid{
			Header:             header.Deneb,
			BlobKZGCommitments: payload.Deneb.BlobsBundle.Commitments,
			Value:              value,
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
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version))
	}
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *VersionedSignedBlindedBeaconBlock, blockPayload *builderApi.VersionedSubmitBlindedBlockResponse) (*VersionedSignedProposal, error) {
	signedBeaconBlock := VersionedSignedProposal{
		eth2Api.VersionedSignedProposal{ //nolint:exhaustruct
			Version: signedBlindedBeaconBlock.Version,
		},
	}
	switch signedBlindedBeaconBlock.Version {
	case spec.DataVersionCapella:
		capellaBlindedBlock := signedBlindedBeaconBlock.Capella
		signedBeaconBlock.Capella = CapellaUnblindSignedBlock(capellaBlindedBlock, blockPayload.Capella)
	case spec.DataVersionDeneb:
		denebBlindedBlock := signedBlindedBeaconBlock.Deneb
		if len(denebBlindedBlock.Message.Body.BlobKZGCommitments) != len(blockPayload.Deneb.BlobsBundle.Blobs) {
			return nil, errors.New("number of blinded blobs does not match blobs bundle length")
		}

		signedBeaconBlock.Deneb = DenebUnblindSignedBlock(denebBlindedBlock, blockPayload.Deneb)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", signedBlindedBeaconBlock.Version))
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
				BLSToExecutionChanges: blindedBlock.Message.Body.BLSToExecutionChanges,
			},
		},
	}
}

func DenebUnblindSignedBlock(blindedBlock *eth2ApiV1Deneb.SignedBlindedBeaconBlock, blockPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle) *eth2ApiV1Deneb.SignedBlockContents {
	return &eth2ApiV1Deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message: &deneb.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &deneb.BeaconBlockBody{
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
					BLSToExecutionChanges: blindedBlock.Message.Body.BLSToExecutionChanges,
					BlobKZGCommitments:    blindedBlock.Message.Body.BlobKZGCommitments,
				},
			},
			Signature: blindedBlock.Signature,
		},
		KZGProofs: blockPayload.BlobsBundle.Proofs,
		Blobs:     blockPayload.BlobsBundle.Blobs,
	}
}

type BuilderBlockValidationRequest struct {
	*VersionedSubmitBlockRequest
	RegisteredGasLimit    uint64
	ParentBeaconBlockRoot *phase0.Root
}

type capellaBuilderBlockValidationRequestJSON struct {
	Message            *builderApiV1.BidTrace    `json:"message"`
	ExecutionPayload   *capella.ExecutionPayload `json:"execution_payload"`
	Signature          string                    `json:"signature"`
	RegisteredGasLimit uint64                    `json:"registered_gas_limit,string"`
}

type denebBuilderBlockValidationRequestJSON struct {
	Message               *builderApiV1.BidTrace       `json:"message"`
	ExecutionPayload      *deneb.ExecutionPayload      `json:"execution_payload"`
	BlobsBundle           *builderApiDeneb.BlobsBundle `json:"blobs_bundle"`
	Signature             string                       `json:"signature"`
	RegisteredGasLimit    uint64                       `json:"registered_gas_limit,string"`
	ParentBeaconBlockRoot string                       `json:"parent_beacon_block_root"`
}

func (r *BuilderBlockValidationRequest) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return json.Marshal(&capellaBuilderBlockValidationRequestJSON{
			Message:            r.Capella.Message,
			ExecutionPayload:   r.Capella.ExecutionPayload,
			Signature:          r.Capella.Signature.String(),
			RegisteredGasLimit: r.RegisteredGasLimit,
		})
	case spec.DataVersionDeneb:
		return json.Marshal(&denebBuilderBlockValidationRequestJSON{
			Message:               r.Deneb.Message,
			ExecutionPayload:      r.Deneb.ExecutionPayload,
			BlobsBundle:           r.Deneb.BlobsBundle,
			Signature:             r.Deneb.Signature.String(),
			RegisteredGasLimit:    r.RegisteredGasLimit,
			ParentBeaconBlockRoot: r.ParentBeaconBlockRoot.String(),
		})
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

type VersionedSubmitBlockRequest struct {
	builderSpec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) MarshalSSZ() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return r.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
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

func (r *VersionedSubmitBlockRequest) HashTreeRoot() (phase0.Root, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return r.Capella.HashTreeRoot()
	case spec.DataVersionDeneb:
		return r.Deneb.HashTreeRoot()
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return phase0.Root{}, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
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

type VersionedSignedProposal struct {
	eth2Api.VersionedSignedProposal
}

func (r *VersionedSignedProposal) MarshalSSZ() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return r.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalSSZ(input []byte) error {
	var err error
	denebRequest := new(eth2ApiV1Deneb.SignedBlockContents)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(capella.SignedBeaconBlock)
	if err = capellaRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSignedProposal) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalJSON(input []byte) error {
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
	return errors.Wrap(err, "failed to unmarshal SignedProposal")
}

type VersionedSignedBlindedBeaconBlock struct {
	eth2Api.VersionedSignedBlindedBeaconBlock
}

func (r *VersionedSignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalJSON(input []byte) error {
	var err error

	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, denebBlock); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
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
