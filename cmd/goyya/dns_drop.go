package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	nfqueue "github.com/AkihiroSuda/go-netfilter-queue"
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
	defer nfq.Close()

	packets := getPktChan(nfq)

	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-packets:
			processDNSPacket(pkt, db)
		}
	}
}

func buildAdServerDb(adservers string) map[string]BlockConf {
	db := make(map[string]BlockConf, 2000)

	return db
}

func addDnsDropTable() {

	conf := fmt.Sprintf(`
table inet dns_drop {
	chain c {
		type filter hook prerouting priority filter; policy accept;
		meta l4proto udp udp dport 53 queue num %d bypass
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
	log.Print(pkt.Packet)
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
