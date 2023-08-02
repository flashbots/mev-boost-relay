package common

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/spec"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	consensusdeneb "github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utildeneb "github.com/attestantio/go-eth2-client/util/deneb"
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

func BuildGetHeaderResponse(payload *VersionedSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*spec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	versionedPayload := &api.VersionedExecutionPayload{Version: payload.Version}
	switch payload.Version {
	case consensusspec.DataVersionCapella:
		versionedPayload.Capella = payload.Capella.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &spec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionCapella,
			Capella: signedBuilderBid.Capella,
		}, nil
	case consensusspec.DataVersionDeneb:
		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &spec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionDeneb,
			Deneb:   signedBuilderBid.Deneb,
		}, nil
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		return nil, ErrInvalidVersion
	default:
		return nil, ErrEmptyPayload
	}
}

func BuildGetPayloadResponse(payload *VersionedSubmitBlockRequest) (*api.VersionedSubmitBlindedBlockResponse, error) {
	if payload.Capella != nil {
		return &api.VersionedSubmitBlindedBlockResponse{
			Version: consensusspec.DataVersionCapella,
			Capella: payload.Capella.ExecutionPayload,
		}, nil
	}

	return nil, ErrEmptyPayload
}

func BuilderBlockRequestToSignedBuilderBid(payload *VersionedSubmitBlockRequest, header *api.VersionedExecutionPayloadHeader, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*spec.VersionedSignedBuilderBid, error) {
	value, err := payload.Value()
	if err != nil {
		return nil, err
	}

	switch payload.Version {
	case consensusspec.DataVersionCapella:
		builderBid := capella.BuilderBid{
			Value:  value,
			Header: header.Capella,
			Pubkey: *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &spec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionCapella,
			Capella: &capella.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case consensusspec.DataVersionDeneb:
		var blobRoots []phase0.Root
		for i, blob := range payload.Deneb.BlobsBundle.Blobs {
			blobRootHelper := utildeneb.BeaconBlockBlob{Blob: blob}
			root, err := blobRootHelper.HashTreeRoot()
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to calculate blob root at blob index %d", i))
			}
			blobRoots = append(blobRoots, root)
		}
		blindedBlobRoots := deneb.BlindedBlobsBundle{
			Commitments: payload.Deneb.BlobsBundle.Commitments,
			Proofs:      payload.Deneb.BlobsBundle.Proofs,
			BlobRoots:   blobRoots,
		}

		builderBid := deneb.BuilderBid{
			Value:              value,
			Header:             header.Deneb,
			BlindedBlobsBundle: &blindedBlobRoots,
			Pubkey:             *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &spec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionDeneb,
			Deneb: &deneb.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version.String()))
	}
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *VersionedSignedBlindedBlockRequest, blockPayload *api.VersionedSubmitBlindedBlockResponse) (*VersionedSignedBlockRequest, error) {
	signedBeaconBlock := VersionedSignedBlockRequest{
		consensusapi.VersionedBlockRequest{ //nolint:exhaustruct
			Version: signedBlindedBeaconBlock.Version,
		},
	}
	switch signedBlindedBeaconBlock.Version {
	case consensusspec.DataVersionCapella:
		capellaBlindedBlock := signedBlindedBeaconBlock.Capella
		signedBeaconBlock.Capella = CapellaUnblindSignedBlock(capellaBlindedBlock, blockPayload.Capella)
	case consensusspec.DataVersionDeneb:
		denebBlindedBlock := signedBlindedBeaconBlock.Deneb.SignedBlindedBlock
		blockRoot, err := denebBlindedBlock.Message.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		signedBeaconBlock.Deneb = DenebUnblindSignedBlock(denebBlindedBlock, blockPayload.Deneb, blockRoot)
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", signedBlindedBeaconBlock.Version.String()))
	}
	return &signedBeaconBlock, nil
}

func CapellaUnblindSignedBlock(blindedBlock *apiv1capella.SignedBlindedBeaconBlock, executionPayload *consensuscapella.ExecutionPayload) *consensuscapella.SignedBeaconBlock {
	return &consensuscapella.SignedBeaconBlock{
		Signature: blindedBlock.Signature,
		Message: &consensuscapella.BeaconBlock{
			Slot:          blindedBlock.Message.Slot,
			ProposerIndex: blindedBlock.Message.ProposerIndex,
			ParentRoot:    blindedBlock.Message.ParentRoot,
			StateRoot:     blindedBlock.Message.StateRoot,
			Body: &consensuscapella.BeaconBlockBody{
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

func DenebUnblindSignedBlock(blindedBlock *apiv1deneb.SignedBlindedBeaconBlock, blockPayload *deneb.ExecutionPayloadAndBlobsBundle, blockRoot phase0.Root) *apiv1deneb.SignedBlockContents {
	denebBlobSidecars := make([]*consensusdeneb.BlobSidecar, len(blockPayload.BlobsBundle.Blobs))

	for i := range denebBlobSidecars {
		denebBlobSidecars[i] = &consensusdeneb.BlobSidecar{
			BlockRoot:       blockRoot,
			Index:           consensusdeneb.BlobIndex(i),
			Slot:            blindedBlock.Message.Slot,
			BlockParentRoot: blindedBlock.Message.ParentRoot,
			ProposerIndex:   blindedBlock.Message.ProposerIndex,
			Blob:            blockPayload.BlobsBundle.Blobs[i],
			KzgCommitment:   blockPayload.BlobsBundle.Commitments[i],
			KzgProof:        blockPayload.BlobsBundle.Proofs[i],
		}
	}
	return &apiv1deneb.SignedBlockContents{
		Message: &apiv1deneb.BlockContents{
			Block: &consensusdeneb.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &consensusdeneb.BeaconBlockBody{
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
			BlobSidecars: denebBlobSidecars,
		},
		Signature: blindedBlock.Signature,
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
	spec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZ(input []byte) error {
	var err error

	deneb := new(deneb.SubmitBlockRequest)
	if err = deneb.UnmarshalSSZ(input); err == nil {
		r.Version = consensusspec.DataVersionDeneb
		r.Deneb = deneb
		return nil
	}

	capella := new(capella.SubmitBlockRequest)
	if err = capella.UnmarshalSSZ(input); err == nil {
		r.Version = consensusspec.DataVersionCapella
		r.Capella = capella
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case consensusspec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case consensusspec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	deneb := new(deneb.SubmitBlockRequest)
	if err = json.Unmarshal(input, deneb); err == nil {
		r.Version = consensusspec.DataVersionDeneb
		r.Deneb = deneb
		return nil
	}
	capella := new(capella.SubmitBlockRequest)
	if err = json.Unmarshal(input, capella); err == nil {
		r.Version = consensusspec.DataVersionCapella
		r.Capella = capella
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest")
}

type VersionedSignedBlockRequest struct {
	consensusapi.VersionedBlockRequest
}

func (r *VersionedSignedBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case consensusspec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case consensusspec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSignedBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	deneb := new(apiv1deneb.SignedBlockContents)
	if err = json.Unmarshal(input, deneb); err == nil {
		r.Version = consensusspec.DataVersionDeneb
		r.Deneb = deneb
		return nil
	}

	capella := new(consensuscapella.SignedBeaconBlock)
	if err = json.Unmarshal(input, capella); err == nil {
		r.Version = consensusspec.DataVersionCapella
		r.Capella = capella
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SignedBeaconBlockRequest")
}

type VersionedSignedBlindedBlockRequest struct {
	consensusapi.VersionedBlindedBlockRequest
}

func (r *VersionedSignedBlindedBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case consensusspec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case consensusspec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSignedBlindedBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	deneb := new(apiv1deneb.SignedBlindedBlockContents)
	if err = json.Unmarshal(input, deneb); err == nil {
		r.Version = consensusspec.DataVersionDeneb
		r.Deneb = deneb
		return nil
	}

	capella := new(apiv1capella.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, capella); err == nil {
		r.Version = consensusspec.DataVersionCapella
		r.Capella = capella
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SignedBlindedBeaconBlock")
}
