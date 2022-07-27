package website

import (
	"text/template"

	"github.com/flashbots/boost-relay/database"
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
	Payloads                    []*database.DeliveredPayloadEntry
}

func parseIndexTemplate() (*template.Template, error) {
	return template.New("index").Parse(`
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">

    <title>Flashbots Boost Relay - {{ .Network }}</title>

    <meta name="description" content="Flashbots testing relay for maximal extractable value in Ethereum proof-of-stake.">
    <link data-react-helmet="true" rel="shortcut icon" href="https://writings.flashbots.net/img/favicon.ico">

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

        .pure-table tr:hover td  {
            background: #129fea1f !important;
        }
    </style>
</head>

<body>


    <div class="grids">
        <div class="content">
            <p>
                <img style="float:right;" src="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />
            <h1>
                Flashbots Boost Relay - {{ .Network }}
            </h1>

			<p>
            Configuration:
            <ul>
				<li>Relay Pubkey: <tt>{{ .RelayPubkey }}</tt></li>
                <li>Bellatrix fork version: <tt>{{ .BellatrixForkVersion }}</tt></li>
                <li>Genesis fork version: <tt>{{ .GenesisForkVersion }}</tt></li>
                <li>Genesis validators root: <tt>{{ .GenesisValidatorsRoot }}</tt></li>
                <li>Builder signing domain: <tt>{{ .BuilderSigningDomain }}</tt></li>
                <li>Beacon proposer signing domain: <tt>{{ .BeaconProposerSigningDomain }}</tt></li>
            </ul>
            </p>

            <p>
			More infos, issues &amp; feedback:
            <ul>
                <li><a href="https://github.com/flashbots/mev-boost">github.com/flashbots/mev-boost</a></li>
            </ul>

            </p>

            <hr>

            <p>
            <h2>
				Stats
            </h2>
            <ul>
                <li>Latest Slot: {{ .HeadSlot }}</li>
                <li>Validators<br>
                    <ul>
                        <li>Total: {{ .ValidatorsTotal }}</li>
                        <li>Registered: {{ .ValidatorsRegistered }}</li>
                    </ul>
            </ul>
            </p>

            <hr>

            <p>
            <h2>
                Recently Delivered Payloads
            </h2>

            <table class="pure-table pure-table-horizontal pure-table-striped">
            <thead>
                <tr>
                    <th>Epoch</th>
                    <th>Slot</th>
                    <th>Block number</th>
                    <th>Parent hash</th>
                    <th>Block hash</th>
                    <th>Num tx</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Payloads }}
                    <tr>
                        <td>{{.Epoch}}</td>
                        <td>{{.Slot}}</td>
                        <td>{{.BlockNumber}}</td>
                        <td>{{.ParentHash}}</td>
                        <td>{{.BlockHash}}</td>
                        <td>{{.NumTx}}</td>
                        <td>{{.Value}}</td>
                    </tr>
                {{ end }}
            </tbody>
            </table>
            </p>
        </div>
    </div>
</body>

</html>
`)
}
