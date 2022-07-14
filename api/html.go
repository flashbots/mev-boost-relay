package api

import "text/template"

type StatusHTMLData struct {
	RelayPubkey                 string
	ValidatorsTotal             string
	ValidatorsRegistered        string
	BellatrixForkVersion        string
	GenesisForkVersion          string
	GenesisValidatorsRoot       string
	BuilderSigningDomain        string
	BeaconProposerSigningDomain string
	Header                      string
	Block                       string
}

func parseIndexTemplate() (*template.Template, error) {
	return template.New("index").Parse(`
<!DOCTYPE html>
<html lang="en" class="no-js">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">

    <title>Boost Block Builder</title>

    <meta name="description" content="MEV builder API">

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
    </style>
</head>

<body>


    <div class="grids">
        <div class="content">
            <p>
                <img style="float:right;" src="https://d33wubrfki0l68.cloudfront.net/ae8530415158fbbbbe17fb033855452f792606c7/fe19f/img/logo.png" />
            <h1>
                Boost Block Builder
            </h1>

			<p>
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
			More details:
            <ul>
                <li><a href="https://github.com/flashbots/mev-boost/wiki">github.com/flashbots/mev-boost/wiki</a></li>
                <li>Issues & feedback: 
				<ul>
				<li><a href="https://github.com/flashbots/mev-boost/issues">github.com/flashbots/mev-boost/issues</a></li></li>
					<li><a href="https://github.com/flashbots/boost-geth-builder/issues">github.com/flashbots/boost-geth-builder/issues</a></li>
				</ul>
            </ul>

            </p>

            <hr>

            <p>
            <h2>
				Validators: {{ .ValidatorsRegistered }} / {{ .ValidatorsTotal }}
            </h2>
            </p>

            <hr>

            <p>
            <h2>
                Best Header
            </h2>
            <pre>coming again soon{{ .Header }}</pre>
            </p>

            <hr>

            <p>
            <h2>
                Best Payload
            </h2>
            <pre>coming again soon{{ .Block }}</pre>
            </p>

        </div>
    </div>
</body>

</html>
`)
}
