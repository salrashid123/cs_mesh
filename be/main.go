package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	port = flag.String("port", ":18082", "port")
)

const ()

func healthz(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("healthcheck")
	fmt.Fprint(w, "ok")
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("get")

	hostname, err := os.Hostname()
	if err != nil {
		http.Error(w, "Error getting hostname", http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text/plain")
		return
	}
	fmt.Fprint(w, fmt.Sprintf("be %s", hostname))
}

func main() {

	flag.Parse()
	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthz)
	router.Methods(http.MethodGet).Path("/getbe").HandlerFunc(gethandler)

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
