package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
)

var (
	beaconURIs = common.GetSliceEnv("BEACON_URIS", []string{"http://localhost:3500"})
	log        *logrus.Entry
)

func main() {
	log = common.LogSetup(false, "info")

	log.Infof("Using beacon endpoints: %s", strings.Join(beaconURIs, ", "))
	for _, uri := range beaconURIs {
		beaconInstance := beaconclient.NewProdBeaconInstance(log, uri)
		go subscribeHead(beaconInstance)
		go subscribePayloadAttr(beaconInstance)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func subscribeHead(instance *beaconclient.ProdBeaconInstance) {
	_log := log.WithField("beacon", instance.GetURI())
	_log.Info("subscribeHead")
	c := make(chan beaconclient.HeadEventData)
	go instance.SubscribeToHeadEvents(c)
	for {
		headEvent := <-c
		_log.WithField("timestamp", time.Now().UTC().UnixMilli()).Infof("headEvent: slot=%d", headEvent.Slot)
	}
}

func subscribePayloadAttr(instance *beaconclient.ProdBeaconInstance) {
	_log := log.WithField("beacon", instance.GetURI())
	_log.Info("subscribePayloadAttr")
	c := make(chan beaconclient.PayloadAttributesEvent)
	go instance.SubscribeToPayloadAttributesEvents(c)
	for {
		event := <-c
		_log.WithField("timestamp", time.Now().UTC().UnixMilli()).Infof("payloadAttrEvent: slot=%d / parent=%s / randao=%s", event.Data.ProposalSlot, event.Data.ParentBlockHash, event.Data.PayloadAttributes.PrevRandao)
	}
}
