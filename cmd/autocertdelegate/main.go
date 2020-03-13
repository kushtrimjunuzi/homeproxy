package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/kushtrimjunuzi/autocertdelegate"
	"golang.org/x/crypto/acme/autocert"
)

var (
	addr     = flag.String("addr", ":8000", "listening port")
	hosts    = flag.String("hosts", "", "Whitelisted host names, use comma separated for multiple")
	certsdir = flag.String("certsdir", "autocerts", "Dir for storing certs")
)

func main() {
	flag.Parse()

	//default no host policy
	hwl := func(ctx context.Context, host string) error { return nil }
	if hosts != nil && *hosts != "" {
		hp := []string{}
		for _, h := range strings.Split(*hosts, ",") {
			hp = append(hp, strings.TrimSpace(h))
		}
		if len(hp) > 0 {
			hwl = autocert.HostWhitelist(hp...)
		}
	}
	// this is for actual cert delegation internally
	m := &autocert.Manager{
		Cache:      autocert.DirCache(*certsdir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hwl,
	}

	s := &http.Server{
		Handler:   autocertdelegate.NewServer(m),
		Addr:      *addr,
		TLSConfig: m.TLSConfig(),
	}
	fmt.Println("running on port ", *addr)

	err := s.ListenAndServeTLS("", "")
	if err != nil {
		fmt.Println("error:", err)
	}
}
