package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"proxy/check"
	"time"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {

	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	file, err := os.Create(filepath.Join("requests", filepath.Base("last_req_" + req.Host + ".txt")))
	defer file.Close()

	req.Write(file)
	if err != nil {
		fmt.Print(err)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {


	server := &http.Server{
		Addr: ":8081",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}


	serverForRepeating := &http.Server{
		Addr: ":8082",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fileName, _ := r.URL.Query()["file"]

			content, err := ioutil.ReadFile(filepath.Join("requests", filepath.Base(fileName[0])))
			if err != nil {
				fmt.Println(err)
			}

			readerBytes := bytes.NewReader(content)
			readerBufio := bufio.NewReader(readerBytes)
			newReq, err := http.ReadRequest(readerBufio)
			newReq.RequestURI = "http://" + newReq.Host
			newReq.URL.Scheme = "http"
			newReq.URL.Host = newReq.Host
			resp, err := http.DefaultTransport.RoundTrip(newReq)

			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer resp.Body.Close()
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)


			vulnerability, err := check.Checking(newReq)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Vulnerability is", vulnerability)
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	go serverForRepeating.ListenAndServe()

	log.Println("Proxy server started on 8081 port")
	log.Fatal(server.ListenAndServe())

}