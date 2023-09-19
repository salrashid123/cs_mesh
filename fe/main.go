package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	port = flag.String("port", ":18081", "port")

	serverName       = flag.String("serverName", "be.service.consul", "SNI to connect to")
	serverCertRootCA = flag.String("serverCertRootCA", "/envoy/ca.pem", "Root CA of the server cert")

	clientCert = flag.String("clientCert", "/envoy/client.crt", "Client Certificate to use")
	clientKey  = flag.String("clientKey", "/envoy/client.key", "Client cert key")

	caFile = flag.String("caFile", "/consul/consul-agent-ca.pem", "CA for consul")

	dnsResolverIP        = "127.0.0.1:8600"
	dnsResolverProto     = "tcp"
	dnsResolverTimeoutMs = 1000
)

const ()

func healthz(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("healthcheck")
	fmt.Fprint(w, "ok")
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("get")
	fmt.Fprint(w, "fe")
}

func getbehandler(w http.ResponseWriter, r *http.Request) {

	caCert, err := ioutil.ReadFile(*serverCertRootCA)
	if err != nil {
		http.Error(w, "Error reading server certrootca", http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	cert1, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		http.Error(w, "Error reading server keypair", http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return
	}

	tlsConfig := &tls.Config{
		ServerName:   *serverName,
		RootCAs:      serverCertPool,
		Certificates: []tls.Certificate{cert1},
		MinVersion:   tls.VersionTLS13,
	}

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	tr.DialContext = dialContext
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://be.service.consul:8082/getbe")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		return
	}
	defer resp.Body.Close()

	fmt.Fprint(w, string(htmlData))
}

func main() {

	flag.Parse()
	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthz)
	router.Methods(http.MethodGet).Path("/getfe").HandlerFunc(gethandler)
	router.Methods(http.MethodGet).Path("/getbe").HandlerFunc(getbehandler)

	var err error

	server := &http.Server{
		Addr:    *port,
		Handler: router,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServe()
	fmt.Printf("Unable to start Server %v", err)

}
