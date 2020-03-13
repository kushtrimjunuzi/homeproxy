package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/kushtrimjunuzi/autocertdelegate"
	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const secretTypeURL = "type.googleapis.com/envoy.api.v2.auth.Secret"

var (
	addr      = flag.String("addr", "/tmp/envoysds.sock", "unix socket")
	delegator = flag.String("delegator", "certs.yourdomain.com", "auto cert delegate server")
	refresh   = flag.Duration("refresh", time.Second*20, "Fetch all certificates after this time")
)

func main() {
	flag.Parse()

	_, err := os.Stat(*addr)
	if err == nil {
		log.Printf("The path %s already exists, removing it.\n", *addr)

		// remove here just in case the process was stopped incorrectly
		err = os.Remove(*addr)
		if err != nil {
			log.Printf("error when removing %s", err)
		}
	}
	chsig := make(chan os.Signal, 1)

	listener, err := net.Listen("unix", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on the unix socket %s: %v\n", *addr, err)
	}

	udsServer := grpc.NewServer()
	signal.Notify(chsig)
	go handleSignals(chsig, udsServer, *addr)

	sds.RegisterSecretDiscoveryServiceServer(udsServer, New(*delegator, *refresh))

	log.Printf("starting the server")
	if err = udsServer.Serve(listener); err != nil {
		log.Fatalf("Failed to launch SDS on UDS: %v", err)
	}
}

func handleSignals(chnl <-chan os.Signal, svr *grpc.Server, udsPath string) {
	for sig := range chnl {
		go func(sig os.Signal) {
			if sig == syscall.SIGTERM || sig == syscall.SIGKILL || sig == syscall.SIGINT {
				log.Printf("sig: %v\n", sig)
				if _, err := os.Stat(udsPath); err == nil {
					// More likely that udsPath exists.
					// Likely, not certain because another
					// handler may have removed the file in
					// the meantime. But likelihood of existing
					// goes up with this check.
					//
					// We ignore errors
					svr.GracefulStop()
					os.Remove(udsPath)
				}
			}
		}(sig)
	}
}

func getPublicCert(cert *tls.Certificate) ([]byte, error) {
	// contains PEM-encoded data
	var buf bytes.Buffer
	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func getPrivateCert(cert *tls.Certificate) ([]byte, error) {
	// contains PEM-encoded data
	var buf bytes.Buffer

	// private
	switch key := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		if err := encodeECDSAKey(&buf, key); err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(key)
		pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("cmd/envoysds: unknown private key type")
	}
	return buf.Bytes(), nil
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

type EnvoySDS struct {
	delegator   string
	certRefresh time.Duration
}

func New(delegator string, certRefresh time.Duration) *EnvoySDS {
	return &EnvoySDS{
		delegator:   delegator,
		certRefresh: certRefresh,
	}
}

func (s *EnvoySDS) newVersion() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// gets certificate from autocertdelegate server
func (s *EnvoySDS) GetTLSCertificate(name string) (*auth.TlsCertificate, error) {

	c := autocertdelegate.NewClient(s.delegator)
	tls, err := c.GetCertificate(&tls.ClientHelloInfo{
		ServerName: name,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		SupportedProtos: []string{
			"h2",
			"http/1.1",     // enable HTTP/2
			acme.ALPNProto, // enable tls-alpn ACME challenges
		},
	})
	if err != nil {
		return nil, err
	}

	pubcert, err := getPublicCert(tls)
	if err != nil {
		return nil, err
	}
	privcert, err := getPrivateCert(tls)
	if err != nil {
		return nil, err
	}

	tlsSecret := &auth.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{pubcert},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{privcert},
		},
	}

	return tlsSecret, err
}

// prapare the response to sds
func (s *EnvoySDS) makeSecret(names []string, version string) (*api.DiscoveryResponse, error) {

	resources := []*any.Any{}
	for _, rs := range names {
		tlsCertificate, err := s.GetTLSCertificate(rs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to read TLS certificate (%v)", err)
		}
		secret := &auth.Secret{
			Name: rs,
			Type: &auth.Secret_TlsCertificate{
				TlsCertificate: tlsCertificate,
			},
		}
		data, err := proto.Marshal(secret)
		if err != nil {
			errMessage := fmt.Sprintf("Generates invalid secret (%v)", err)
			log.Println(errMessage)
			return nil, status.Errorf(codes.Internal, errMessage)
		}
		resources = append(resources, &any.Any{
			TypeUrl: secretTypeURL,
			Value:   data,
		})
	}

	response := &api.DiscoveryResponse{
		Resources:   resources,
		TypeUrl:     secretTypeURL,
		VersionInfo: version,
	}

	return response, nil
}

func (s *EnvoySDS) FetchSecrets(ctx context.Context, request *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {
	return s.makeSecret(request.ResourceNames, s.newVersion())
}

func (s *EnvoySDS) DeltaSecrets(stream sds.SecretDiscoveryService_DeltaSecretsServer) error {
	err := "DeltaSecrets not implemented."
	log.Println(err)
	return status.Errorf(codes.Unimplemented, err)
}

func (s *EnvoySDS) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	log.Println("process stream service")
	reset := make(chan []string)
	names := []string{}
	version := ""

	//TODO: implement better worker
	go func(r chan []string) {
		for {
			select {
			case <-stream.Context().Done():
				return
			case names := <-r: // reset worker signal
				log.Printf("reset worker for names: %v", names)

				version = s.newVersion()
				secret, err := s.makeSecret(names, version)
				if err != nil {
					fmt.Println(err)
					return
				}
				if err := stream.Send(secret); err != nil {
					fmt.Println(err)
					return
				}
			}
		}
	}(reset)

	// every x duration, send reset signal for worker to fetch all certificates
	go func(reset chan []string) {
		for {
			select {
			case <-stream.Context().Done():
				return
			case <-time.After(s.certRefresh):
				reset <- names
			}
		}
	}(reset)

	for {

		r, err := stream.Recv()
		if err != nil {
			fmt.Println(err)
			return err
		}

		if r.ErrorDetail != nil {
			log.Printf("skip, error detail: %v", r.ErrorDetail)
			continue
		}
		names = r.ResourceNames

		if r.VersionInfo != "" && r.VersionInfo == version {
			continue
		}

		log.Printf("request resources: %v", names)

		version = s.newVersion()
		secret, err := s.makeSecret(names, version)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if err := stream.Send(secret); err != nil {
			return err
		}

		log.Printf("sent resources: %v", names)
	}
}
