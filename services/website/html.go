package website

import (
	"math/big"
	"text/template"

	"github.com/flashbots/mev-boost-relay/database"
)

type StatusHTMLData struct {
	Network                     string
	RelayPubkey                 string
	ValidatorsTotal             string
	ValidatorsRegistered        string
	BellatrixForkVersion        string
	GenesisForkVersion          string
	GenesisValidatorsRoot       string
	BuilderSigningDomain        string
	BeaconProposerSigningDomain string
	HeadSlot                    string
	NumPayloadsDelivered        string
	Payloads                    []*database.DeliveredPayloadEntry
	ValueLink                   string
	ValueOrderIcon              string
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

var funcMap = template.FuncMap{
	"weiToEth": weiToEth,
}

func ParseIndexTemplate() (*template.Template, error) {
	return template.New("index").Funcs(funcMap).Parse(`
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">

    <title>Flashbots MEV-Boost Relay - {{ .Network }}</title>
    <meta name="description" content="Flashbots MEV-Boost Relay enables Ethereum proof-of-stake validators access to blocks with maximal extractable value">

    <link data-react-helmet="true" rel="shortcut icon" href="https://writings.flashbots.net/img/favicon.ico">

    <meta property="og:title" content="Flashbots MEV-Boost Relay" />
    <meta property="og:description" content="Flashbots MEV-Boost Relay enables Ethereum proof-of-stake validators access to blocks with maximal extractable value" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Flashbots MEV-Boost Relay" />
    <meta property="og:image" content="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />
    <meta property="og:image:url" content="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />
    <meta property="og:image:alt" content="Flashbots logo" />

    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="Flashbots MEV-Boost Relay" />
    <meta property="twitter:description" content="Flashbots MEV-Boost Relay enables Ethereum proof-of-stake validators access to blocks with maximal extractable value" />
    <meta property="twitter:image" content="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />

    <link rel="stylesheet" href="https://unpkg.com/purecss@2.1.0/build/pure-min.css" integrity="sha384-yHIFVG6ClnONEA5yB5DJXfW2/KC173DIQrYoZMEtBvGzmf0PKiGyNEqe9N6BNDBH" crossorigin="anonymous">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style type="text/css">
        body {
            padding: 10px 40px;
        }

        pre {
            text-align: left;
        }

        hr {
            border-top: 1px solid #e5e5e5;
            margin: 40px 0;
        }

        tt {
            font-size: 1.2em;
            background: #129fea1f;
        }

        li {
            margin: 2px 0px;
        }

        .pure-table thead {
            background-color: #129fea1f;
        }

        .pure-table tr:hover td {
            background: #129fea1f !important;
        }
    </style>
</head>

<body>


    <div class="grids">
        <div class="content">
            <img style="float:right;"
                src="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />
            <h1>
                Flashbots Boost Relay - {{ .Network }}
            </h1>

            <p>
                Configuration:
            </p>
            <ul>
                <li>Relay Pubkey: <tt>{{ .RelayPubkey }}</tt></li>
                <li>Bellatrix fork version: <tt>{{ .BellatrixForkVersion }}</tt></li>
                <li>Genesis fork version: <tt>{{ .GenesisForkVersion }}</tt></li>
                <li>Genesis validators root: <tt>{{ .GenesisValidatorsRoot }}</tt></li>
                <li>Builder signing domain: <tt>{{ .BuilderSigningDomain }}</tt></li>
                <li>Beacon proposer signing domain: <tt>{{ .BeaconProposerSigningDomain }}</tt></li>
            </ul>

            <p>
                More infos, issues &amp; feedback:
            </p>
            <ul>
                <li><a href="https://flashbots.notion.site/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5">Relay API
                        docs</a></li>
                <li><a href="http://boost.flashbots.net">boost.flashbots.net</a></li>
                <li><a href="https://github.com/flashbots/mev-boost">github.com/flashbots/mev-boost</a></li>
                <li><a
                        href="https://github.com/flashbots/boost-geth-builder">github.com/flashbots/boost-geth-builder</a>
                </li>
            </ul>

            <hr>

            <p>
            <h2>
                Stats
            </h2>

            <ul>
                <li>Validators total: {{ .ValidatorsTotal }}</li>
                <li>Validators registered: {{ .ValidatorsRegistered }}</li>
                <li>Latest slot: {{ .HeadSlot }}</li>
            </ul>

            </p>

            <hr>

            <p>
            <h2>
                Recently Delivered Payloads
            </h2>

            <table class="pure-table pure-table-horizontal pure-table-striped" style="width:100%;">
                <thead>
                    <tr>
                        <th>Epoch</th>
                        <th>Slot</th>
                        <th>Block number</th>
                        <th>
                            Value (ETH{{.ValueOrderIcon}})

                            <a href="{{.ValueLink}}">
                                <svg id="icon-sort-default" style="float:right; width:16px;" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M3 7.5L7.5 3m0 0L12 7.5M7.5 3v13.5m13.5 0L16.5 21m0 0L12 16.5m4.5 4.5V7.5" />
                                </svg>
                            </a>
                        </th>
                        <th>Num tx</th>
                        <th>Block hash</th>
                    </tr>
                </thead>
                <tbody>
                    {{ range .Payloads }}
                    <tr>
                        <td>{{.Epoch}}</td>
                        <td>
                            <a href="/relay/v1/data/bidtraces/proposer_payload_delivered?slot={{.Slot}}">{{.Slot}}</a>
                        </td>
                        <td>{{.BlockNumber}}</td>
                        <td>{{.Value | weiToEth}}</td>
                        <td>{{.NumTx}}</td>
                        <td>{{.BlockHash}}</td>
                    </tr>
                    {{ end }}
                </tbody>
            </table>
            </p>


            <center>
                <p>

                    {{.NumPayloadsDelivered}} payloads delivered</p>
                <p>
                    <a href="/relay/v1/data/bidtraces/proposer_payload_delivered?limit=10">Data API</a> / <a href="https://flashbots.notion.site/Relay-API-Spec-5fb0819366954962bc02e81cb33840f5#417abe417dde45caaff3dc15aaae65dd">Docs</a></p>
            </center>
        </div>
    </div>
</body>

</html>
`)
}
