package website

import (
	_ "embed"
	"math/big"
	"text/template"
	"time"

	"github.com/flashbots/mev-boost-relay/database"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var (
	// Printer for pretty printing numbers
	printer = message.NewPrinter(language.English)

	// Caser is used for casing strings
	caser = cases.Title(language.English)
)

type StatusHTMLData struct { //nolint:musttag
	Network                     string
	RelayPubkey                 string
	ValidatorsTotal             uint64
	ValidatorsRegistered        uint64
	BellatrixForkVersion        string
	CapellaForkVersion          string
	GenesisForkVersion          string
	GenesisValidatorsRoot       string
	BuilderSigningDomain        string
	BeaconProposerSigningDomain string
	HeadSlot                    uint64
	NumPayloadsDelivered        uint64
	Payloads                    []*database.DeliveredPayloadEntry

	ValueLink      string
	ValueOrderIcon string

	ShowConfigDetails bool
	LinkBeaconchain   string
	LinkEtherscan     string
	LinkDataAPI       string
	RelayURL          string
}

func weiToEth(wei string) string {
	weiBigInt := new(big.Int)
	weiBigInt.SetString(wei, 10)
	ethValue := weiBigIntToEthBigFloat(weiBigInt)
	return ethValue.String()
}

func weiBigIntToEthBigFloat(wei *big.Int) (ethValue *big.Float) {
	// wei / 10^18
	fbalance := new(big.Float)
	fbalance.SetString(wei.String())
	ethValue = new(big.Float).Quo(fbalance, big.NewFloat(1e18))
	return
}

func prettyInt(i uint64) string {
	return printer.Sprintf("%d", i)
}

func caseIt(s string) string {
	return caser.String(s)
}

func relativeTime(t time.Time) string {
	diff := time.Since(t)
	if diff < 0 {
		// should be unreachable, but just in case
		return diff.String()
	}

	seconds := int(diff.Seconds())
	minutes := int(diff.Minutes())
	hours := int(diff.Hours())
	days := hours / 24

	if seconds < 60 {
		return printer.Sprintf("%ds ago", seconds)
	} else if minutes < 60 {
		return printer.Sprintf("%dm ago", minutes)
	} else if hours < 24 {
		return printer.Sprintf("%dh ago", hours)
	} else {
		return printer.Sprintf("%dd ago", days)
	}
}

func formatUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

var funcMap = template.FuncMap{
	"weiToEth":     weiToEth,
	"prettyInt":    prettyInt,
	"caseIt":       caseIt,
	"relativeTime": relativeTime,
	"formatUTC":    formatUTC,
}

//go:embed website.html
var htmlContent string

func ParseIndexTemplate() (*template.Template, error) {
	return template.New("index").Funcs(funcMap).Parse(htmlContent)
}
