package website

import (
	"text/template"
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
	// Payloads                    []*database.DeliveredPayloadEntry
}

func parseIndexTemplate() (*template.Template, error) {
	return template.New("index").Parse(`
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">

    <title>Flashbots Boost Relay - {{ .Network }}</title>

    <meta name="description"
        content="Flashbots testing relay for maximal extractable value in Ethereum proof-of-stake.">
    <link data-react-helmet="true" rel="shortcut icon" href="https://writings.flashbots.net/img/favicon.ico">
    <meta property="og:image"
        content="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />

    <link rel="stylesheet" href="https://unpkg.com/purecss@2.1.0/build/pure-min.css"
        integrity="sha384-yHIFVG6ClnONEA5yB5DJXfW2/KC173DIQrYoZMEtBvGzmf0PKiGyNEqe9N6BNDBH" crossorigin="anonymous">
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
                        <!--<th>Parent hash</th>-->
                        <th>Block hash</th>
                        <th>Num tx</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {{ range .Payloads }}
                    <tr>
                        <td>{{.Epoch}}</td>
                        <td><a href="/relay/v1/data/bidtraces/proposer_payload_delivered?slot={{.Slot}}">{{.Slot}}</a>
                        </td>
                        <td>{{.BlockNumber}}</td>
                        <td>{{.BlockHash}}</td>
                        <!--<td>{{.ParentHash}}</td>-->
                        <td>{{.NumTx}}</td>
                        <td>{{.Value}}</td>
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
