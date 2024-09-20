package mevcommitclient

type IMevCommitClient interface {
	// Need to provide some SLA's around response times here. Should be down to milliseconds with memcache.
	IsValidatorRegistered(pubkey string) (bool, error)
	IsBuilderRegistered(pubkey string) (bool, error)
	GetRegisteredValidators() ([]string, error)
}

type MevCommitClient struct {
	L1Address        string // 0x5d4fC7B5Aeea4CF4F0Ca6Be09A2F5AaDAd2F2803 created at 1731009 block
	MevCommitAddress string
}

func NewMevCommitClient(apiUrl string) IMevCommitClient {
	return &MevCommitClient{
		apiUrl: apiUrl,
	}
}
