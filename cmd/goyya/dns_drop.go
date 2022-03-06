package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DNS_QUEUE  = 0
	QUEUE_SIZE = 50
)

type BlockConf struct {
}

func dropDNSAds(ctx context.Context, adservers string) {

	addDnsDropTable()
	defer deleteDnsDroptable()

	db := buildAdServerDb(adservers)

	nfqctx, nfqCancel := context.WithCancel(ctx)
	defer nfqCancel()

	nfq := registerNFQ(nfqctx,
		func(pkt gopacket.Packet) int {
			return processDNSPacket(pkt, db)
		})
	if nfq == nil {
		log.Print("unable to register nfq")
		return
	}
	defer nfq.Close()

	<-ctx.Done()

	log.Print("stop drop dns")
}

func buildAdServerDb(adservers string) map[string]BlockConf {
	db := make(map[string]BlockConf, 2000)

	return db
}

func addDnsDropTable() {

	conf := fmt.Sprintf(`
table inet dns_drop {
}

delete table inet dns_drop

table inet dns_drop {
	chain c_pre {
		type filter hook prerouting priority filter; policy accept;
		meta l4proto udp udp dport 53 queue num %[1]d bypass
	}

	chain c_post {
		type filter hook postrouting priority filter; policy accept;
		meta l4proto udp udp dport 53 queue num %[1]d bypass
	}
}
`,
		DNS_QUEUE)
	runNft(conf)

}

func deleteDnsDroptable() {
	runNft(`
delete table inet dns_drop
`)
}

func runNft(config string) {
	f, err := os.CreateTemp("", "goyyo-*.nft")
	if err != nil {
		log.Print("Error creating a temp file", err)
		return
	}
	defer f.Close()

	_, err = f.Write([]byte(config))
	if err != nil {
		log.Print("Error writing config", err)
		return
	}
	f.Close()

	cmd := exec.Command("nft", "-f", f.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Print("Error running nft", config,
			"\n---- ouput:", string(output),
			"\n----error:", err)
		return
	}
}

func registerNFQ(ctx context.Context, fn pktProcessFn) *nfqueue.Nfqueue {
	config := nfqueue.Config{
		NfQueue:      DNS_QUEUE,
		MaxPacketLen: 3000,
		MaxQueueLen:  QUEUE_SIZE,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
		Logger:       log.Default(),
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Print("could not open nfqueue socket:", err)
		return nil
	}

	err = nf.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			return hookFn(nf, a, fn)
		}, func(e error) int {
			if err != nil {
				log.Print("ErrFN: ", err)
			}
			return 0
		})
	if err != nil {
		log.Print("could not register fn", err)
		return nil
	}

	return nf
}

func hookFn(nf *nfqueue.Nfqueue, a nfqueue.Attribute, fn pktProcessFn) int {
	if a.PacketID == nil {
		log.Print("Unable to deref Packet details")
		return 0
	}
	id := *a.PacketID
	if a.Payload == nil {
		log.Print("Unable to deref Packet details")
		err := nf.SetVerdict(id, nfqueue.NfAccept)
		if err != nil {
			log.Print("SetVerdict err", err)
		}
		return 0
	}

	payload := *a.Payload

	var decoder gopacket.Decoder
	if payload[0]&0xf0 == 0x40 {
		decoder = layers.LayerTypeIPv4
	} else {
		decoder = layers.LayerTypeIPv6
	}

	pkt := gopacket.NewPacket(
		payload,
		decoder,
		gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true},
	)

	verdict := fn(pkt)
	err := nf.SetVerdict(id, verdict)
	if err != nil {
		log.Print("SetVerdict err", err)
	}

	return 0
}

type pktProcessFn func(gopacket.Packet) int

func processDNSPacket(pkt gopacket.Packet, db map[string]BlockConf) int {
	log.Print("got a pkt")
	switch proto := pkt.ApplicationLayer().(type) {
	case *layers.DNS:
		for i, qs := range proto.Questions {
			log.Println("Question", i, ":", string(qs.Name))
		}
	}

	return nfqueue.NfAccept
}
