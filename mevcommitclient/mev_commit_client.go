package mevcommitclient

type IMevCommitClient interface {
	// Need to provide some SLA's around response times here. Should be down to milliseconds with memcache.
	IsValidatorRegistered(pubkey string) (bool, error)
	IsBuilderRegistered(pubkey string) (bool, error)
}

type MevCommitClient struct {
	L1Address        string
	MevCommitAddress string
}

func NewMevCommitClient(apiUrl string) IMevCommitClient {
	return &MevCommitClient{
		apiUrl: apiUrl,
	}
}
