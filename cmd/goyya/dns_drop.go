package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	nfqueue "github.com/AkihiroSuda/go-netfilter-queue"
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
	nfq, err := nfqueue.NewNFQueue(DNS_QUEUE, QUEUE_SIZE, nfqueue.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Print("Error opening nfqueue", err)
		return
	}
	// defer nfq.Close() // TODO why is it blocking?

	packets := getPktChan(nfq)

dnsLoop:
	for {
		select {
		case <-ctx.Done():
			break dnsLoop
		case pkt := <-packets:
			processDNSPacket(pkt, db)
		}
	}

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

func processDNSPacket(pkt nfqueue.NFPacket, db map[string]BlockConf) {
	log.Print("got a  pkt")
	switch proto := pkt.Packet.ApplicationLayer().(type) {
	case *layers.DNS:
		for _, qs := range proto.Questions {
			log.Println("Question", string(qs.Name))
		}
	}
	pkt.SetVerdict(nfqueue.NF_ACCEPT)
}

func getPktChan(nfq *nfqueue.NFQueue) <-chan nfqueue.NFPacket {
	packets := make(chan nfqueue.NFPacket, QUEUE_SIZE)
	go func() {
		for p := range nfq.GetPackets() {
			packets <- p
		}
	}()
	return packets
}
