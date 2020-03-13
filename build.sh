#!/bin/sh

func_gobuild(){
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o cmd/autocertdelegate/autocertdelegate cmd/autocertdelegate/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o cmd/envoysds/envoysds cmd/envoysds/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o cmd/envoytmpl/envoytmpl cmd/envoytmpl/main.go
}

func_docker(){
	docker build --rm=true -t kushtrimjunuzi/autocertdelegate -f docker/autocertdelegate/Dockerfile .
	docker build --rm=true -t kushtrimjunuzi/envoysds -f docker/envoysds/Dockerfile .
	docker build --rm=true -t kushtrimjunuzi/tlsrouter docker/tlsrouter
	docker build --rm=true -t kushtrimjunuzi/envoy -f docker/envoy/Dockerfile .
}

# This service is used for two reasons, do Let's Encrypt ALPN challenges and option to fetch those certificates locally
# Public-facing service, this service is a "fake" service that pretend to be all of your web apps your have declared in ./config/envoy.yaml, so that 
# when Let's Encrypt try to do ALPN challenges it will hit this service in public-facing side and as soon it validates it will store tls certificate in 
# defined dir in your container which in this example is /autocerts.

# This service is accessed in local network to fetch the tls certificates that are being created.
# When accessing from internal network it is pointing to local IP, when accessing from outside your network (ex. try from mobile data only) 
# it is pointing to your router public IP, in other words this is called split-horizon DNS.
# Any dns server you have can configure a domain as split-horizon DNS, in pfsense for example you can do that in Services -> DNS Resolver -> Host Overrides 
# just add your autocertdelegate domain (ex. certs.yourdomain.com) here and your IP in this case is 10.0.6.7
# In order to configure for public accessing you need to port forward in your NAT, in pfsense you can do that in Firewall -> NAT and add new entry:
# Interface: WAN
# Protocol: TCP
# Destination: WAN
# Destination Port range: from port: HTTPS, to port HTTPS
# Redirect Target IP: 10.0.6.7 
# Redirect Target port rage: from HTTPS, to port HTTPS
# NAT reflection: Use system default
# Filter rule association: Add associated filter rule

# After this is done it will add new rule in your firewall to allow 443 port in your router and from this moment your router is serving port 443 publicly
# it is ideal to setup also the dynamic DNS https://docs.netgate.com/pfsense/en/latest/dns/dynamic-dns.html so that when ISP changes your public ip it will also dynamically change your DNS records in your public DNS registry.
func_run_autocertdelegate(){

	docker rm -f autocertdelegate
	docker volume create autocertdelegate-data
	docker run \
		--name autocertdelegate \
		-d \
		--restart=always \
		--network host \
		-v "autocertdelegate-data:/autocerts" \
		kushtrimjunuzi/autocertdelegate /bin/autocertdelegate -addr 10.0.6.7:8602 -certsdir "/autocerts"

}

# Provide dynamic tls certificates for envoy proxy, as soon the envoy container is started it will contact autocertdelegate 
# and fetch all tls certificates for all domains configured in ./config/envoy.yaml
# also will re-fetch after -refresh duraton so that it will dynamically renew certificates no need for envoy to restart
# By default the autocertdelegate will renew certificates automatically before 30 days of expiration (sorry, I have not tested this), you can change that if you want in autocertdelegate source code.
func_run_envoysds(){
	#private facing service

	AUTOCERTDELEGATE=${AUTOCERTDELEGATE:="certs.yourdomain.com"}
	docker rm -f envoysds
	docker volume create envoysds-data
	docker run \
		--name envoysds \
		-d \
		--restart=always \
		--network=host \
		-v "envoysds-data:/envoysds" \
		kushtrimjunuzi/envoysds /bin/envoysds -addr "/envoysds/envoysds.sock" -delegator "$AUTOCERTDELEGATE" -refresh 360h
}

# this proxy is used for easy proxing all tls traffic to downstream which is autocertdelegate container
# in your ./config/tlsrouter.config be sure to write all your domains, attempt to not use wildcard(*.yourdomain.com) because of less attack surface and less public reachable 
# tlsrouter has its own IP for easy provisioning in your firewall, you can use any IP your net supports
# this host is configured with 3 network interfaces, host has its own IP, tlsrouter has its own IP and envoy proxy has its own IP, you can configure however you like this is just an example
func_run_tlsrouter(){
	# public facing proxy

	docker rm -f tlsrouter
	docker run \
		--name tlsrouter \
		-d \
		-v "${PWD}/config:/config" \
		--restart=always \
		--network=host \
		kushtrimjunuzi/tlsrouter /bin/tlsrouter -conf /config/tlsrouter.config -listen 10.0.6.7:443

}

# this is main proxy for all your web apps, use different IP for this proxy and different for tlsrouter
func_run_envoy(){
	# private facing proxy

	docker rm -f envoy
	docker run \
		--name envoy \
		-d \
		-v "${PWD}/config:/config" \
		--restart=always \
		--add-host "docker1:10.0.6.6" \
		-v "envoysds-data:/envoysds" \
		--network host \
		kushtrimjunuzi/envoy /usr/local/bin/envoy -c /config/envoy.yaml
}

func_run(){
	func_run_autocertdelegate
	func_run_envoysds
	func_run_tlsrouter
	func_run_envoy
}

func_envoytmpl(){
	# generate envoy yaml file
	docker run --rm -v "${PWD}/config:/config" \
		kushtrimjunuzi/envoy /bin/envoytmpl -tmpl /config/envoy.yaml.tmpl -config /config/envoy.config.json -out /config/envoy.yaml
}

# copy all templates into ./config dir so that you can modify them based on your needs
# ./config dir is mounted in some docker containers
func_copy_templates(){
	mkdir -p config
	cp -i cmd/envoytmpl/envoy.yaml.tmpl config/
	cp -i cmd/envoytmpl/envoy.config.json config/
	cp -i docker/tlsrouter/tlsrouter.config config/
	cp -i ./build.sh config/
}

RUN=$1
case "$RUN" in
	build)
		func_gobuild
		func_docker
		;;
	gobuild)
		func_gobuild
		;;
	docker)
		func_docker
		;;
	run-autocertdelegate)
		func_run_autocertdelegate
		;;
	run-envoysds)
		func_run_envoysds
		;;
	run-tlsrouter)
		func_run_tlsrouter
		;;
	run-envoy)
		func_run_envoy
		;;
	run)
		func_run
		;;
	envoytmpl)
		func_envoytmpl
		;;
	copy-templates)
		func_copy_templates
		;;
	*)
	echo "Usage: $1 {build|gobuild|docker|run|run-autocertdelegate|run-envoysds|run-tlsrouter|run-envoy|envoytmpl}"
	exit 1
esac


