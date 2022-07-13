package common

import (
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

const (
	GenesisForkVersionMainnet = "0x00000000"
	GenesisForkVersionKiln    = "0x70000069"
	GenesisForkVersionRopsten = "0x80000069"
	GenesisForkVersionSepolia = "0x90000069"

	GenesisValidatorsRootKiln    = "0x99b09fcd43e5905236c370f184056bec6e6638cfc31a323b304fc4aa789cb4ad"
	GenesisValidatorsRootRopsten = "0x44f1e56283ca88b35c789f7f449e52339bc1fefe3a45913a43a6d16edcd33cf1"
	GenesisValidatorsRootSepolia = "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"
	GenesisValidatorsRootMainnet = ""
)

// BuilderEntry represents a builder that is allowed to send blocks
// Address will be schema://hostname:port
type BuilderEntry struct {
	Address string
	Pubkey  hexutil.Bytes
	URL     *url.URL
}

// NewBuilderEntry creates a new instance based on an input string
// builderURL can be IP@PORT, PUBKEY@IP:PORT, https://IP, etc.
func NewBuilderEntry(builderURL string) (entry *BuilderEntry, err error) {
	if !strings.HasPrefix(builderURL, "http") {
		builderURL = "http://" + builderURL
	}

	url, err := url.Parse(builderURL)
	if err != nil {
		return entry, err
	}

	entry = &BuilderEntry{
		URL:     url,
		Address: entry.URL.Scheme + "://" + entry.URL.Host,
	}
	err = entry.Pubkey.UnmarshalText([]byte(entry.URL.User.Username()))
	return entry, err
}
