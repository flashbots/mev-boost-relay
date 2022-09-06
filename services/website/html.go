package website

import (
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

func parseIndexTemplate() (*template.Template, error) {
	return template.New("index").Parse(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width">
        <meta name="description"
            content="SecureRpc Relay - credible neutral  maximal extractable value service layer fon Ethereum proof-of-stake.">
     
        <link data-react-helmet="true" rel="shortcut icon" rel="icon"  href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔐</text></svg>"/>
    
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
        <link rel="manifest" href="/site.webmanifest">
    
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2.1.1/out/water.min.css" integrity="sha256-QST90Wzz4PEr5KlclQaOCsjc00FTyf86Wrj41oqZB4w=" crossorigin="anonymous">
    
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
    
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="SecureRpc Relay ">
    <meta property="og:title" content="SecureRpc Relay ">
    <meta
      name="description"
      content="DeFi JSON-RPC for Optimized Trade Execution, Frontrunning Protection, and Maximal Extracted Value protection"
    />
    <meta name="copyright" content="2022 CommodityStream, Inc" />
    <meta name="robots" content="index, follow" />
    <meta name="rating" content="general" />
    </head>
    
    <body>
    
        <div class=" grids">
            <div class=" content">
                <img style="float:right;">
    
    <h1>
        ⍜ SecureRpc Relay
    </h1>
    <hr>
    <h2>
        🌐 {{ .Network }} 
    </h2>
    <ul>
       <li> ✓ Relay Pubkey: <tt>{{ .RelayPubkey }}</tt></li>
       <li> ✓ Bellatrix fork version: <tt>{{ .BellatrixForkVersion }}</tt></li>
       <li> ✓ Genesis fork version: <tt>{{ .GenesisForkVersion }}</tt></li>
       <li> ✓ Genesis validators root: <tt>{{ .GenesisValidatorsRoot }}</tt></li>
       <li> ✓ Builder signing domain: <tt>{{ .BuilderSigningDomain }}</tt></li>
       <li> ✓ Beacon proposer signing domain: <tt>{{ .BeaconProposerSigningDomain }}</tt></li>
    </ul>
    <hr>
    <p>
    <h2>
        ℹ️  Stats
    </h2>  
    <ul>
       <li>📶  Validators total: {{ .ValidatorsTotal }}</li>
       <li>🔄 Validators registered: {{ .ValidatorsRegistered }}</li>
       <li>↪️ Latest slot: {{ .HeadSlot }}</li>
    </ul>
    <hr>
    <p>
    <h2>
     ↪️ Recently Delivered Payloads
    </h2>
    <table class=" pure-table pure-table-horizontal pure-table-striped" style="width:100%;">
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
    <br> 
    <div> 
    
       <p>
        #️⃣  Total Payloads Delivered: {{.NumPayloadsDelivered}}
       </p>
    
       <br>
       <p style="text-align:center">
         . . . 
       </p>
    </div>
    </div>
    </div>
    
    <h2>🛠 Developers</h2>
    <p>
        <a href="/relay/v1/data/bidtraces/proposer_payload_delivered?limit=10">Data API</a> / <a href="http://kb.manifoldfinance.com/docs/MEV">Docs</a>
     </p>
     <ul>
        <li><a href="http://kb.manifoldfinance.com/docs/MEV">SecureRpc Relay API specification</a>
        </li>
        <li><a href="http://kb.manifoldfinance.com">Documentation</a></li>
        <li><a href="https://github.com/manifoldfinance/mev-boost">GitHub</a></li>
        <li><a
           href="https://manifoldfinance.github.io/primitives">Engineering Blog</a>
        </li>
     </ul>
    <br>
    
    <footer>
        <div>
          <span>
            <a target="_top" href="https://manifoldfinance.com">
           <p>ⓒ 2022 - CommodityStream Inc. <br /> </p>  
            </a>
          </span>
          <span>
              <a href="#">Back to top ⬆</a>
          </span>
        </div>
        </footer>
    
    </body>
    </html>
`)
}
