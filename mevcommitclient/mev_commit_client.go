package mevcommitclient

type IMevCommitClient interface {
	IsValidatorRegistered(pubkey string) (bool, error)
	IsBuilderRegistered(pubkey string) (bool, error)
}

type MevCommitClient struct {
	L1Address string
	MevCommitAddress string
}

func NewMevCommitClient(apiUrl string) IMevCommitClient {
	return &MevCommitClient{
		apiUrl: apiUrl,
	}
}