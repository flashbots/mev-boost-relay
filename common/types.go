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
