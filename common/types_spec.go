package common

import (
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	eth2ApiV1Capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2ApiV1Electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	eth2ApiV1Fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/goccy/go-json"
	"github.com/holiman/uint256"
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
	case spec.DataVersionElectra:
		versionedPayload.Electra = payload.Electra.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: signedBuilderBid.Electra,
		}, nil

	case spec.DataVersionFulu:
		versionedPayload.Fulu = payload.Fulu.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionFulu,
			Fulu:    signedBuilderBid.Fulu,
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
	case spec.DataVersionElectra:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionElectra,
			Electra: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: payload.Electra.ExecutionPayload,
				BlobsBundle:      payload.Electra.BlobsBundle,
			},
		}, nil
	case spec.DataVersionFulu:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionFulu,
			Fulu: &builderApiFulu.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: payload.Fulu.ExecutionPayload,
				BlobsBundle:      payload.Fulu.BlobsBundle,
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
	case spec.DataVersionElectra:
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Electra,
			BlobKZGCommitments: payload.Electra.BlobsBundle.Commitments,
			ExecutionRequests:  payload.Electra.ExecutionRequests,
			Value:              value,
			Pubkey:             *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: &builderApiElectra.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case spec.DataVersionFulu:
		// The BuilderBid type for fulu is the same as that of electra
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Fulu,
			BlobKZGCommitments: payload.Fulu.BlobsBundle.Commitments,
			ExecutionRequests:  payload.Fulu.ExecutionRequests,
			Value:              value,
			Pubkey:             *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionFulu,
			Fulu: &builderApiElectra.SignedBuilderBid{
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
	case spec.DataVersionElectra:
		electraBlindedBlock := signedBlindedBeaconBlock.Electra
		if len(electraBlindedBlock.Message.Body.BlobKZGCommitments) != len(blockPayload.Electra.BlobsBundle.Blobs) {
			return nil, errors.New("number of blinded blobs does not match blobs bundle length")
		}
		signedBeaconBlock.Electra = ElectraUnblindSignedBlock(electraBlindedBlock, blockPayload.Electra)
	case spec.DataVersionFulu:
		fuluBlindedBlock := signedBlindedBeaconBlock.Fulu
		if len(fuluBlindedBlock.Message.Body.BlobKZGCommitments) != len(blockPayload.Fulu.BlobsBundle.Blobs) {
			return nil, errors.New("number of blinded blobs does not match blobs bundle length")
		}
		signedBeaconBlock.Fulu = FuluUnblindSignedBlock(fuluBlindedBlock, blockPayload.Fulu)
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

func ElectraUnblindSignedBlock(blindedBlock *eth2ApiV1Electra.SignedBlindedBeaconBlock, blockPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle) *eth2ApiV1Electra.SignedBlockContents {
	return &eth2ApiV1Electra.SignedBlockContents{
		SignedBlock: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &electra.BeaconBlockBody{
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
					ExecutionRequests:     blindedBlock.Message.Body.ExecutionRequests,
				},
			},
			Signature: blindedBlock.Signature,
		},
		KZGProofs: blockPayload.BlobsBundle.Proofs,
		Blobs:     blockPayload.BlobsBundle.Blobs,
	}
}

func FuluUnblindSignedBlock(blindedBlock *eth2ApiV1Electra.SignedBlindedBeaconBlock, blockPayload *builderApiFulu.ExecutionPayloadAndBlobsBundle) *eth2ApiV1Fulu.SignedBlockContents {
	return &eth2ApiV1Fulu.SignedBlockContents{
		SignedBlock: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &electra.BeaconBlockBody{
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
					ExecutionRequests:     blindedBlock.Message.Body.ExecutionRequests,
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

type electraBuilderBlockValidationRequestJSON struct {
	Message               *builderApiV1.BidTrace       `json:"message"`
	ExecutionPayload      *deneb.ExecutionPayload      `json:"execution_payload"`
	BlobsBundle           *builderApiDeneb.BlobsBundle `json:"blobs_bundle"`
	ExecutionRequests     *electra.ExecutionRequests   `json:"execution_requests"`
	Signature             string                       `json:"signature"`
	RegisteredGasLimit    uint64                       `json:"registered_gas_limit,string"`
	ParentBeaconBlockRoot string                       `json:"parent_beacon_block_root"`
}

type fuluBuilderBlockValidationRequestJSON struct {
	Message               *builderApiV1.BidTrace      `json:"message"`
	ExecutionPayload      *deneb.ExecutionPayload     `json:"execution_payload"`
	BlobsBundle           *builderApiFulu.BlobsBundle `json:"blobs_bundle"`
	ExecutionRequests     *electra.ExecutionRequests  `json:"execution_requests"`
	Signature             string                      `json:"signature"`
	RegisteredGasLimit    uint64                      `json:"registered_gas_limit,string"`
	ParentBeaconBlockRoot string                      `json:"parent_beacon_block_root"`
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
	case spec.DataVersionElectra:
		return json.Marshal(&electraBuilderBlockValidationRequestJSON{
			Message:               r.Electra.Message,
			ExecutionPayload:      r.Electra.ExecutionPayload,
			BlobsBundle:           r.Electra.BlobsBundle,
			ExecutionRequests:     r.Electra.ExecutionRequests,
			Signature:             r.Electra.Signature.String(),
			RegisteredGasLimit:    r.RegisteredGasLimit,
			ParentBeaconBlockRoot: r.ParentBeaconBlockRoot.String(),
		})
	case spec.DataVersionFulu:
		return json.Marshal(&fuluBuilderBlockValidationRequestJSON{
			Message:               r.Fulu.Message,
			ExecutionPayload:      r.Fulu.ExecutionPayload,
			BlobsBundle:           r.Fulu.BlobsBundle,
			ExecutionRequests:     r.Fulu.ExecutionRequests,
			Signature:             r.Fulu.Signature.String(),
			RegisteredGasLimit:    r.RegisteredGasLimit,
			ParentBeaconBlockRoot: r.ParentBeaconBlockRoot.String(),
		})
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

type BuilderBlockValidationResponse struct {
	BlockValue *uint256.Int `json:"block_value"` // true block value calculated from simulation
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
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	case spec.DataVersionFulu:
		return r.Fulu.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZ(input []byte) error {
	var err error
	fuluRequest := new(builderApiFulu.SubmitBlockRequest)
	if err = fuluRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionFulu
		r.Fulu = fuluRequest
		return nil
	}
	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
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
	case spec.DataVersionElectra:
		return r.Electra.HashTreeRoot()
	case spec.DataVersionFulu:
		return r.Fulu.HashTreeRoot()
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
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	case spec.DataVersionFulu:
		return json.Marshal(r.Fulu)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalWithVersion(input []byte, contentType, ethConsensusVersion string) error {
	if contentType == ApplicationOctetStream {
		if err := r.UnmarshalSSZWithVersion(input, ethConsensusVersion); err != nil {
			// builder might submit a json payload with the an octet-stream content type.
			if err2 := r.UnmarshalJSONWithVersion(input, ethConsensusVersion); err2 != nil {
				return err2
			}
		}
	} else {
		if err := r.UnmarshalJSONWithVersion(input, ethConsensusVersion); err != nil {
			return err
		}
	}
	return nil
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZWithVersion(input []byte, ethConsensusVersion string) error {
	switch ethConsensusVersion {
	case EthConsensusVersionBellatrix:
		r.Version = spec.DataVersionBellatrix
		r.Bellatrix = new(builderApiBellatrix.SubmitBlockRequest)
		return r.Bellatrix.UnmarshalSSZ(input)
	case EthConsensusVersionCapella:
		r.Version = spec.DataVersionCapella
		r.Capella = new(builderApiCapella.SubmitBlockRequest)
		return r.Capella.UnmarshalSSZ(input)
	case EthConsensusVersionDeneb:
		r.Version = spec.DataVersionDeneb
		r.Deneb = new(builderApiDeneb.SubmitBlockRequest)
		return r.Deneb.UnmarshalSSZ(input)
	case EthConsensusVersionElectra:
		r.Version = spec.DataVersionElectra
		r.Electra = new(builderApiElectra.SubmitBlockRequest)
		return r.Electra.UnmarshalSSZ(input)
	case EthConsensusVersionFulu:
		r.Version = spec.DataVersionFulu
		r.Fulu = new(builderApiFulu.SubmitBlockRequest)
		return r.Fulu.UnmarshalSSZ(input)
	default:
		return ErrInvalidForkVersion
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalJSONWithVersion(input []byte, ethConsensusVersion string) error {
	switch ethConsensusVersion {
	case EthConsensusVersionBellatrix:
		r.Version = spec.DataVersionBellatrix
		r.Bellatrix = new(builderApiBellatrix.SubmitBlockRequest)
		return r.Bellatrix.UnmarshalJSON(input)
	case EthConsensusVersionCapella:
		r.Version = spec.DataVersionCapella
		r.Capella = new(builderApiCapella.SubmitBlockRequest)
		return r.Capella.UnmarshalJSON(input)
	case EthConsensusVersionDeneb:
		r.Version = spec.DataVersionDeneb
		r.Deneb = new(builderApiDeneb.SubmitBlockRequest)
		return r.Deneb.UnmarshalJSON(input)
	case EthConsensusVersionElectra:
		r.Version = spec.DataVersionElectra
		r.Electra = new(builderApiElectra.SubmitBlockRequest)
		return r.Electra.UnmarshalJSON(input)
	case EthConsensusVersionFulu:
		r.Version = spec.DataVersionFulu
		r.Fulu = new(builderApiFulu.SubmitBlockRequest)
		return r.Fulu.UnmarshalJSON(input)
	default:
		return ErrInvalidForkVersion
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var err error
	fuluRequest := new(builderApiFulu.SubmitBlockRequest)
	if err = json.Unmarshal(input, fuluRequest); err == nil {
		r.Version = spec.DataVersionFulu
		r.Fulu = fuluRequest
		return nil
	}
	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = json.Unmarshal(input, electraRequest); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
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
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	case spec.DataVersionFulu:
		return r.Fulu.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalSSZ(input []byte) error {
	var err error
	// The SignedBlockContents type for fulu is the same as that of electra
	fuluRequest := new(eth2ApiV1Fulu.SignedBlockContents)
	if err = fuluRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionFulu
		r.Fulu = fuluRequest
		return nil
	}
	electraRequest := new(eth2ApiV1Electra.SignedBlockContents)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
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
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	case spec.DataVersionFulu:
		return json.Marshal(r.Fulu)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalJSON(input []byte) error {
	var err error
	// The SignedBlockContents type for fulu is the same as that of electra
	fuluContents := new(eth2ApiV1Fulu.SignedBlockContents)
	if err = json.Unmarshal(input, fuluContents); err == nil {
		r.Version = spec.DataVersionFulu
		r.Fulu = fuluContents
		return nil
	}
	electraContents := new(eth2ApiV1Electra.SignedBlockContents)
	if err = json.Unmarshal(input, electraContents); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraContents
		return nil
	}
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
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	case spec.DataVersionFulu:
		return json.Marshal(r.Fulu)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalJSON(input []byte) error {
	var err error
	// The SignedBlindedBeaconBlock type for fulu is the same as that of electra
	fuluBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, fuluBlock); err == nil {
		r.Version = spec.DataVersionFulu
		r.Fulu = fuluBlock
		return nil
	}
	electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, electraBlock); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraBlock
		return nil
	}
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

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalSSZWithVersion(input []byte, ethConsensusVersion string) error {
	switch ethConsensusVersion {
	case EthConsensusVersionBellatrix:
		r.Version = spec.DataVersionBellatrix
		r.Bellatrix = new(eth2ApiV1Bellatrix.SignedBlindedBeaconBlock)
		return r.Bellatrix.UnmarshalSSZ(input)
	case EthConsensusVersionCapella:
		r.Version = spec.DataVersionCapella
		r.Capella = new(eth2ApiV1Capella.SignedBlindedBeaconBlock)
		return r.Capella.UnmarshalSSZ(input)
	case EthConsensusVersionDeneb:
		r.Version = spec.DataVersionDeneb
		r.Deneb = new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
		return r.Deneb.UnmarshalSSZ(input)
	case EthConsensusVersionElectra:
		r.Version = spec.DataVersionElectra
		r.Electra = new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		return r.Electra.UnmarshalSSZ(input)
	case EthConsensusVersionFulu:
		r.Version = spec.DataVersionFulu
		r.Fulu = new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		return r.Fulu.UnmarshalSSZ(input)
	default:
		return ErrInvalidForkVersion
	}
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalJSONWithVersion(input []byte, ethConsensusVersion string) error {
	switch ethConsensusVersion {
	case EthConsensusVersionBellatrix:
		r.Version = spec.DataVersionBellatrix
		r.Bellatrix = new(eth2ApiV1Bellatrix.SignedBlindedBeaconBlock)
		return r.Bellatrix.UnmarshalJSON(input)
	case EthConsensusVersionCapella:
		r.Version = spec.DataVersionCapella
		r.Capella = new(eth2ApiV1Capella.SignedBlindedBeaconBlock)
		return r.Capella.UnmarshalJSON(input)
	case EthConsensusVersionDeneb:
		r.Version = spec.DataVersionDeneb
		r.Deneb = new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
		return r.Deneb.UnmarshalJSON(input)
	case EthConsensusVersionElectra:
		r.Version = spec.DataVersionElectra
		r.Electra = new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		return r.Electra.UnmarshalJSON(input)
	case EthConsensusVersionFulu:
		r.Version = spec.DataVersionFulu
		r.Fulu = new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		return r.Fulu.UnmarshalJSON(input)
	default:
		return ErrInvalidForkVersion
	}
}

func (r *VersionedSignedBlindedBeaconBlock) Unmarshal(input []byte, contentType, ethConsensusVersion string) error {
	if contentType == ApplicationOctetStream {
		return r.UnmarshalSSZWithVersion(input, ethConsensusVersion)
	} else if contentType == ApplicationJSON {
		return r.UnmarshalJSONWithVersion(input, ethConsensusVersion)
	}
	return ErrInvalidContentType
}
