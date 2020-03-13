package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"text/template"
)

var (
	tmpl   = flag.String("tmpl", "envoy.yaml.tmpl", "base template file")
	config = flag.String("config", "config.json", "config file that will apply to template")
	out    = flag.String("out", "envoy.yaml", "output file")
)

func main() {
	flag.Parse()

	t := template.Must(template.ParseFiles(*tmpl))

	cfg, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatal(err)
	}

	envoy := &Envoy{}
	if err := json.Unmarshal(cfg, envoy); err != nil {
		log.Fatal(err)
	}

	for _, fc := range envoy.FilterChains {
		// set default routes if non is defined
		if len(fc.Routes) == 0 {
			fc.Routes = []*Route{
				&Route{
					MatchPrefix: "/",
					Timeout:     "60s",
					ClusterName: fc.ClusterName,
					Type:        RouteTypeDefault,
				},
			}
		}
	}

	buf := bytes.NewBuffer([]byte{})
	if err := t.Execute(buf, envoy); err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(*out, buf.Bytes(), 0644); err != nil {
		log.Fatal(err)
	}
}

type Envoy struct {
	FilterChains []*FilterChain `json:"filterChains"`
	Clusters     []*Cluster     `json:"clusters"`
}

type FilterChain struct {
	Domain      string `json:"domain"`
	ClusterName string `json:"clusterName"`

	Routes []*Route `json:"routes"`
}

type Cluster struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type RouteType string

const (
	RouteTypeDefault   RouteType = "default"
	RouteTypeWebSocket           = "websocket"
)

type Route struct {
	MatchPrefix string    `json:"matchPrefix"`
	Type        RouteType `json:"type"`
	Timeout     string    `json:"timeout"`
	ClusterName string    `json:"clusterName"`
}
