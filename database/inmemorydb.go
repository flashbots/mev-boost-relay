package database

import (
	"fmt"
	"sync"
	"time"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/goccy/go-json"
)

// InmemoryDB is an extension of the MockDB that stores the validator registry entries in memory.
type InmemoryDB struct {
	*MockDB

	validatorRegistryEntriesLock sync.Mutex
	validatorRegistryEntries     map[string]*ValidatorRegistrationEntry

	deliveredPayloadsLock sync.Mutex
	deliveredPayloads     []*DeliveredPayloadEntry
}

func NewInmemoryDB() *InmemoryDB {
	return &InmemoryDB{
		MockDB:                   &MockDB{},
		validatorRegistryEntries: make(map[string]*ValidatorRegistrationEntry),
		deliveredPayloads:        make([]*DeliveredPayloadEntry, 0),
	}
}

// -- endpoints for the validator registry ---

func (i *InmemoryDB) NumRegisteredValidators() (count uint64, err error) {
	return uint64(len(i.validatorRegistryEntries)), nil
}

func (i *InmemoryDB) NumValidatorRegistrationRows() (count uint64, err error) {
	return uint64(len(i.validatorRegistryEntries)), nil
}

func (i *InmemoryDB) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	i.validatorRegistryEntriesLock.Lock()
	defer i.validatorRegistryEntriesLock.Unlock()

	i.validatorRegistryEntries[entry.Pubkey] = &entry
	return nil
}

func (i *InmemoryDB) GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error) {
	i.validatorRegistryEntriesLock.Lock()
	defer i.validatorRegistryEntriesLock.Unlock()

	entries := make([]*ValidatorRegistrationEntry, 0, len(i.validatorRegistryEntries))
	for _, entry := range i.validatorRegistryEntries {
		entries = append(entries, entry)
	}
	return entries, nil
}

func (i *InmemoryDB) GetValidatorRegistration(pubkey string) (*ValidatorRegistrationEntry, error) {
	i.validatorRegistryEntriesLock.Lock()
	defer i.validatorRegistryEntriesLock.Unlock()

	entry, found := i.validatorRegistryEntries[pubkey]
	if !found {
		return nil, fmt.Errorf("validator registration not found")
	}
	return entry, nil
}

func (i *InmemoryDB) GetValidatorRegistrationsForPubkeys(pubkeys []string) ([]*ValidatorRegistrationEntry, error) {
	i.validatorRegistryEntriesLock.Lock()
	defer i.validatorRegistryEntriesLock.Unlock()

	entries := make([]*ValidatorRegistrationEntry, 0, len(pubkeys))
	for _, pubkey := range pubkeys {
		entry, found := i.validatorRegistryEntries[pubkey]
		if found {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// -- endpoints for the delivered payloads ---

func (i *InmemoryDB) SaveDeliveredPayload(bidTrace *common.BidTraceV2WithBlobFields, signedBlindedBeaconBlock *common.VersionedSignedBlindedBeaconBlock, signedAt time.Time, publishMs uint64) error {
	i.deliveredPayloadsLock.Lock()
	defer i.deliveredPayloadsLock.Unlock()

	_signedBlindedBeaconBlock, err := json.Marshal(signedBlindedBeaconBlock)
	if err != nil {
		return err
	}

	deliveredPayloadEntry := DeliveredPayloadEntry{
		SignedAt:                 NewNullTime(signedAt),
		SignedBlindedBeaconBlock: NewNullString(string(_signedBlindedBeaconBlock)),

		Slot:  bidTrace.Slot,
		Epoch: bidTrace.Slot / common.SlotsPerEpoch,

		BuilderPubkey:        bidTrace.BuilderPubkey.String(),
		ProposerPubkey:       bidTrace.ProposerPubkey.String(),
		ProposerFeeRecipient: bidTrace.ProposerFeeRecipient.String(),

		ParentHash:  bidTrace.ParentHash.String(),
		BlockHash:   bidTrace.BlockHash.String(),
		BlockNumber: bidTrace.BlockNumber,

		GasUsed:  bidTrace.GasUsed,
		GasLimit: bidTrace.GasLimit,

		NumTx: bidTrace.NumTx,
		Value: bidTrace.Value.ToBig().String(),

		NumBlobs:      bidTrace.NumBlobs,
		BlobGasUsed:   bidTrace.BlobGasUsed,
		ExcessBlobGas: bidTrace.ExcessBlobGas,

		PublishMs: publishMs,
	}

	i.deliveredPayloads = append(i.deliveredPayloads, &deliveredPayloadEntry)
	return nil
}

func (i *InmemoryDB) GetNumDeliveredPayloads() (uint64, error) {
	i.deliveredPayloadsLock.Lock()
	defer i.deliveredPayloadsLock.Unlock()

	return uint64(len(i.deliveredPayloads)), nil
}

func (i *InmemoryDB) GetRecentDeliveredPayloads(filters GetPayloadsFilters) ([]*DeliveredPayloadEntry, error) {
	i.deliveredPayloadsLock.Lock()
	defer i.deliveredPayloadsLock.Unlock()

	entries := []*DeliveredPayloadEntry{}
	for _, entry := range i.deliveredPayloads {
		filtered := filterPayload(entry, filters)
		if !filtered {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func filterPayload(entry *DeliveredPayloadEntry, filter GetPayloadsFilters) bool {
	if filter.BlockNumber != 0 {
		if entry.BlockNumber != uint64(filter.BlockNumber) {
			return true
		}
	}

	if filter.BuilderPubkey != "" {
		if entry.BuilderPubkey != filter.BuilderPubkey {
			return true
		}
	}

	return false
}
