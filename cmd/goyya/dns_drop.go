package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dropsCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "How many HTTP requests processed, partitioned by status code and HTTP method.",
		})
)

const (
	DNS_QUEUE  = 0
	QUEUE_SIZE = 50
)

type BlockConf struct {
}

func dropDNSAds(ctx context.Context, adservers string) {

	prometheus.MustRegister(dropsCounter)

	addDnsDropTable()
	defer deleteDnsDroptable()

	db := buildAdServerDb(adservers)
	if db == nil {
		return
	}

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
	resp, err := http.Get(adservers)
	if err != nil {
		log.Print("Unable to sent GET req to ", adservers, " err:", err)
		return nil
	}
	if resp.StatusCode >= 300 {
		log.Print("Got ", resp.StatusCode, " not successful")
		return nil
	}

	db := make(map[string]BlockConf, 2000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		url, blk, ok := urlFromLine(line)
		if ok {
			db[url] = blk
		}
	}
	log.Printf("Added %d urls", len(db))

	return db
}

// see https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#example-blocking-by-domain-name
func urlFromLine(line string) (string, BlockConf, bool) {

	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		if strings.HasSuffix(line, "^") {
			url := strings.TrimSuffix(line, "^")
			return url, BlockConf{}, true
		}
		if strings.HasSuffix(line, "^$third-party") {
			url := strings.TrimSuffix(line, "^$third-party")
			return url, BlockConf{}, true
		}
	}

	return "", BlockConf{}, false
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
			url := strings.TrimSpace(string(qs.Name))
			log.Println("Question", i, ":", url)

			if isBlockedURL(url, db) {
				log.Println("Blocked ", url)
				dropsCounter.Inc()
				return nfqueue.NfDrop
			}
		}
	}

	return nfqueue.NfAccept
}

func isBlockedURL(url string, db map[string]BlockConf) bool {
	_, ok := db[url]

	return ok
}
