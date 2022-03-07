package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type config struct {
	Adservers   string
	MetricsAddr string
}

func main() {
	log.Println("goyya started")

	conf := parseFlags()
	setupPrometheus(conf.MetricsAddr)

	wg := new(sync.WaitGroup)

	ctx, cancel := context.WithCancel(context.Background())

	// start dns dropper
	wg.Add(1)
	go func() {
		defer wg.Done()
		dropDNSAds(ctx, conf.Adservers)
	}()

	// init done, just wait for signal to stop

	sigInt := make(chan os.Signal, 1)
	signal.Notify(sigInt, os.Interrupt)

	<-sigInt
	cancel()

	log.Println("waiting for threads...")
	wg.Wait()
	log.Println("goyya stopping")
}

func parseFlags() config {
	var (
		configFile string
	)

	flag.StringVar(&configFile, "config", "", "config file")
	flag.Parse()

	if configFile == "" {
		flag.Usage()
		log.Fatalf("Empty configFile '%s', please provide it", configFile)
	}

	contents, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatal("Unable to read configFile", err)
	}

	var config config
	_, err = toml.Decode(string(contents), &config)
	if err != nil {
		log.Fatal("Unable to read configFile", err)
	}

	return config
}

func setupPrometheus(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(addr, nil)
		if err != nil && err != http.ErrServerClosed {
			log.Print("ListenAndServe Err ", err)
		}
	}()
}
