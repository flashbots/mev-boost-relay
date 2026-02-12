package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/flashbots/mev-boost-relay/services/website"
	"github.com/goccy/go-json"
)

func main() {
	var data website.StatusHTMLData

	jsonFile, err := os.Open("testdata/website-htmldata.json")
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close() //nolint:errcheck

	byteValue, _ := io.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		panic(err)
	}

	// add fake times for some variability in rendered template
	diff := time.Second
	for i, v := range data.Payloads {
		v.InsertedAt = time.Now().Add(-diff)
		data.Payloads[i] = v
		diff = diff * 5 / 3
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
