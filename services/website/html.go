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

func parseIndexTemplate() (*template.Template, error) {
	return template.New("index").Funcs(funcMap).Parse(`
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">

    <title>Flashbots MEV-Boost Relay - {{ .Network }}</title>

    <meta name="description"
        content="Flashbots mev-boost relay for maximal extractable value in Ethereum proof-of-stake.">
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

        td{
            white-space: nowrap;
            font-family: monospace;
            font-size: 1.3em !important;
        }

        .beaconchain-icon{
            width: 1em;
            position:relative;
            top: 0.15em;
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
                        <th>Value (ETH)</th>
                        <th>Num tx</th>
                        <th>Block hash</th>
                    </tr>
                </thead>
                <tbody>
                    {{ range .Payloads }}
                    <tr>
                        <td>
                            {{.Epoch}}
                            <a href="https://beaconcha.in/epoch/{{.Epoch}}">
                                <svg class="beaconchain-icon" xmlns="http://www.w3.org/2000/svg" viewBox="263.27 168.54 81.35 101.17">
                                    <path d="M 341.287 198.092 L 340.508 198.289 C 338.293 198.85 337.797 198.496 336.846 196.409 C 335.8 193.738 334.475 191.177 332.89 188.769 C 325.505 178.925 315.692 174.652 303.269 176.552 C 301.781 176.788 300.881 176.336 300.517 174.869 C 300.294 173.884 300.041 172.998 299.829 172.053 C 299.445 170.36 300.001 169.513 301.711 169.208 C 312.434 167.239 322.146 169.631 330.887 175.962 C 337.423 180.697 341.702 187.076 344.363 194.666 C 344.98 196.33 344.484 197.216 342.704 197.708 L 342.704 197.738 Z M 329.865 201.006 C 328.166 201.439 327.842 199.894 326.578 196.94 C 323.522 189.645 315.884 185.189 307.831 186.003 C 305.252 186.259 303.461 186.712 303.117 185.343 C 302.055 181.041 302.237 180.795 306.688 180.421 C 317.858 179.693 328.237 186.055 332.385 196.172 C 332.476 196.419 332.567 196.665 332.678 196.911 C 333.73 199.342 333.366 200.081 330.796 200.77 Z M 323.866 199.923 C 323.927 200.071 323.988 200.228 324.058 200.376 C 324.726 201.882 324.483 202.345 322.824 202.778 L 322.227 202.926 C 321.135 203.201 320.963 202.237 320.133 200.396 C 318.102 195.813 313.219 193.07 308.125 193.652 C 306.455 193.829 305.302 194.125 305.09 193.268 C 304.422 190.581 304.543 190.423 307.406 190.167 C 314.489 189.592 321.142 193.536 323.866 199.923 Z M 274.143 222.713 C 271.866 216.439 271.442 209.669 272.919 203.172 C 273.778 199.234 275.144 198.673 278.473 200.839 C 285.554 205.446 292.515 209.935 300.082 214.838 C 300.82 213.528 301.802 212.278 302.459 210.851 C 302.775 210.139 302.883 209.355 302.773 208.586 C 302.267 205.525 303.785 202.827 306.648 202.138 C 309.515 201.493 312.366 203.272 312.96 206.076 C 313.579 208.883 311.831 211.669 308.985 212.416 C 308.512 212.509 308.076 212.73 307.73 213.056 C 307.558 213.312 304.624 217.899 304.624 217.899 L 315.014 224.889 C 318.525 227.242 322.005 229.575 325.546 231.879 C 329.086 234.182 328.975 235.639 325.738 238.179 C 308.954 251.233 282.104 244.972 274.143 222.713 Z M 263.271 269.704 L 263.271 269.655 C 263.758 268.742 276.643 244.586 277.269 243.948 C 278.645 242.55 298.322 252.808 299.525 254.019 C 299.778 254.275 304.988 269.682 304.988 269.682 L 304.988 269.704 Z"></path>
                                </svg>
                            </a>
                        </td>
                        <td>
                            <a href="/relay/v1/data/bidtraces/proposer_payload_delivered?slot={{.Slot}}">{{.Slot}}</a>
                        </td>
                        <td>
                            {{.BlockNumber}}
                            <a href="https://beaconcha.in/block/{{.BlockNumber}}">
                                <svg class="beaconchain-icon" xmlns="http://www.w3.org/2000/svg" viewBox="263.27 168.54 81.35 101.17">
                                    <path d="M 341.287 198.092 L 340.508 198.289 C 338.293 198.85 337.797 198.496 336.846 196.409 C 335.8 193.738 334.475 191.177 332.89 188.769 C 325.505 178.925 315.692 174.652 303.269 176.552 C 301.781 176.788 300.881 176.336 300.517 174.869 C 300.294 173.884 300.041 172.998 299.829 172.053 C 299.445 170.36 300.001 169.513 301.711 169.208 C 312.434 167.239 322.146 169.631 330.887 175.962 C 337.423 180.697 341.702 187.076 344.363 194.666 C 344.98 196.33 344.484 197.216 342.704 197.708 L 342.704 197.738 Z M 329.865 201.006 C 328.166 201.439 327.842 199.894 326.578 196.94 C 323.522 189.645 315.884 185.189 307.831 186.003 C 305.252 186.259 303.461 186.712 303.117 185.343 C 302.055 181.041 302.237 180.795 306.688 180.421 C 317.858 179.693 328.237 186.055 332.385 196.172 C 332.476 196.419 332.567 196.665 332.678 196.911 C 333.73 199.342 333.366 200.081 330.796 200.77 Z M 323.866 199.923 C 323.927 200.071 323.988 200.228 324.058 200.376 C 324.726 201.882 324.483 202.345 322.824 202.778 L 322.227 202.926 C 321.135 203.201 320.963 202.237 320.133 200.396 C 318.102 195.813 313.219 193.07 308.125 193.652 C 306.455 193.829 305.302 194.125 305.09 193.268 C 304.422 190.581 304.543 190.423 307.406 190.167 C 314.489 189.592 321.142 193.536 323.866 199.923 Z M 274.143 222.713 C 271.866 216.439 271.442 209.669 272.919 203.172 C 273.778 199.234 275.144 198.673 278.473 200.839 C 285.554 205.446 292.515 209.935 300.082 214.838 C 300.82 213.528 301.802 212.278 302.459 210.851 C 302.775 210.139 302.883 209.355 302.773 208.586 C 302.267 205.525 303.785 202.827 306.648 202.138 C 309.515 201.493 312.366 203.272 312.96 206.076 C 313.579 208.883 311.831 211.669 308.985 212.416 C 308.512 212.509 308.076 212.73 307.73 213.056 C 307.558 213.312 304.624 217.899 304.624 217.899 L 315.014 224.889 C 318.525 227.242 322.005 229.575 325.546 231.879 C 329.086 234.182 328.975 235.639 325.738 238.179 C 308.954 251.233 282.104 244.972 274.143 222.713 Z M 263.271 269.704 L 263.271 269.655 C 263.758 268.742 276.643 244.586 277.269 243.948 C 278.645 242.55 298.322 252.808 299.525 254.019 C 299.778 254.275 304.988 269.682 304.988 269.682 L 304.988 269.704 Z"></path>
                                </svg>
                            </a>
                        </td>
                        <td>{{.Value | weiToEth}}</td>
                        <td>{{.NumTx}}</td>
                        <td>
                            {{.BlockHash}}
                            <a href="https://beaconcha.in/block/{{.BlockHash}}">
                                <svg class="beaconchain-icon" xmlns="http://www.w3.org/2000/svg" viewBox="263.27 168.54 81.35 101.17">
                                    <path d="M 341.287 198.092 L 340.508 198.289 C 338.293 198.85 337.797 198.496 336.846 196.409 C 335.8 193.738 334.475 191.177 332.89 188.769 C 325.505 178.925 315.692 174.652 303.269 176.552 C 301.781 176.788 300.881 176.336 300.517 174.869 C 300.294 173.884 300.041 172.998 299.829 172.053 C 299.445 170.36 300.001 169.513 301.711 169.208 C 312.434 167.239 322.146 169.631 330.887 175.962 C 337.423 180.697 341.702 187.076 344.363 194.666 C 344.98 196.33 344.484 197.216 342.704 197.708 L 342.704 197.738 Z M 329.865 201.006 C 328.166 201.439 327.842 199.894 326.578 196.94 C 323.522 189.645 315.884 185.189 307.831 186.003 C 305.252 186.259 303.461 186.712 303.117 185.343 C 302.055 181.041 302.237 180.795 306.688 180.421 C 317.858 179.693 328.237 186.055 332.385 196.172 C 332.476 196.419 332.567 196.665 332.678 196.911 C 333.73 199.342 333.366 200.081 330.796 200.77 Z M 323.866 199.923 C 323.927 200.071 323.988 200.228 324.058 200.376 C 324.726 201.882 324.483 202.345 322.824 202.778 L 322.227 202.926 C 321.135 203.201 320.963 202.237 320.133 200.396 C 318.102 195.813 313.219 193.07 308.125 193.652 C 306.455 193.829 305.302 194.125 305.09 193.268 C 304.422 190.581 304.543 190.423 307.406 190.167 C 314.489 189.592 321.142 193.536 323.866 199.923 Z M 274.143 222.713 C 271.866 216.439 271.442 209.669 272.919 203.172 C 273.778 199.234 275.144 198.673 278.473 200.839 C 285.554 205.446 292.515 209.935 300.082 214.838 C 300.82 213.528 301.802 212.278 302.459 210.851 C 302.775 210.139 302.883 209.355 302.773 208.586 C 302.267 205.525 303.785 202.827 306.648 202.138 C 309.515 201.493 312.366 203.272 312.96 206.076 C 313.579 208.883 311.831 211.669 308.985 212.416 C 308.512 212.509 308.076 212.73 307.73 213.056 C 307.558 213.312 304.624 217.899 304.624 217.899 L 315.014 224.889 C 318.525 227.242 322.005 229.575 325.546 231.879 C 329.086 234.182 328.975 235.639 325.738 238.179 C 308.954 251.233 282.104 244.972 274.143 222.713 Z M 263.271 269.704 L 263.271 269.655 C 263.758 268.742 276.643 244.586 277.269 243.948 C 278.645 242.55 298.322 252.808 299.525 254.019 C 299.778 254.275 304.988 269.682 304.988 269.682 L 304.988 269.704 Z"></path>
                                </svg>
                            </a>
                        </td>
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
