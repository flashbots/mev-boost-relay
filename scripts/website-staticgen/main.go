package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/flashbots/mev-boost-relay/services/website"
)

func main() {
	var data website.StatusHTMLData

	jsonFile, err := os.Open("testdata/website-htmldata.json")
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		panic(err)
	}

	indexTemplate, err := website.ParseIndexTemplate()
	if err != nil {
		panic(err)
	}

	html := bytes.Buffer{}
	if err := indexTemplate.Execute(&html, data); err != nil {
		panic(err)
	}

	if err := os.WriteFile("website-index.html", html.Bytes(), 0o600); err != nil {
		panic(err)
	}

	fmt.Println("Wrote website-index.html")
}
