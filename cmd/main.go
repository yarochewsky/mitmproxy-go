package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"mitmproxy/handler"
	"mitmproxy/pki"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	port = flag.Int("port", 8080, "port to bind server to")

	certFile = flag.String("cert", "cert.crt", "certificate filepath")
	keyFile  = flag.String("key", "cert.key", "key filepath")
)

func main() {
	flag.Parse()

	var ca pki.CertificateAuthority

	cfg := &pki.Config{
		Organization: []string{"Sample Org"},
		Country:      []string{"US"},
		Locality:     []string{"SoHo"},
		StreetAddr:   []string{""},
		PostalCode:   []string{"10001"},
	}

	if _, err := os.Stat(*certFile); err != nil && errors.Is(err, os.ErrNotExist) {
		log.Info("creating ca...")

		ca, err = pki.CreateNewAuthority(cfg)
		if err != nil {
			log.WithError(err).Fatal("failed to create authority")
		}
		if err := ca.SaveAuthority(*keyFile, *certFile); err != nil {
			log.WithError(err).Fatal("failed to save authority to disk")
		}
	} else {
		log.Info("reading ca from disk...")

		ca, err = pki.LoadAuthorityFromDisk(*keyFile, *certFile)
		if err != nil {
			log.WithError(err).Fatal("failed to load authority")
		}
	}

	s := &server{ca}
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), s); err != nil {
		log.WithError(err).Fatal("server failed")
	}
}

type server struct {
	ca pki.CertificateAuthority
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if err := s.handleConnect(w, r); err != nil {
			log.WithError(err).Warn("failed to handle connect")
			w.WriteHeader(http.StatusBadGateway)
		}
	} else if r.URL.IsAbs() {
		s.handleProxy(w, r)
	} else {
		log.Warn("non absolute path or non connect")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *server) handleProxy(w http.ResponseWriter, r *http.Request) {
	httputil.NewSingleHostReverseProxy(r.URL).ServeHTTP(w, r)
}

func getDomain(hostport string) (string, error) {
	host, _, err := net.SplitHostPort(hostport)
	return host, err
}

func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) error {
	domain, err := getDomain(r.Host)
	if err != nil {
		return fmt.Errorf("failed to get domain from host: %v", err)
	}

	pcert, err := s.ca.Sign(domain)
	if err != nil {
		return fmt.Errorf("failed to generate provisional cert: %v", err)
	}
	clientConf := &tls.Config{
		Certificates: []tls.Certificate{*pcert},
	}

	// we establish ourselves as the "server", creating a de-facto
	// TLS client connection
	serverConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// sign a certificate for the server which our client originally wanted
			// to connect to
			cert, err := s.ca.Sign(hello.ServerName)
			if err != nil {
				return nil, fmt.Errorf("could not generate cert: %v", err)
			}

			// this is to verify the server when we connect for our client,
			// avoids using insecureSkipVerify
			clientConf.ServerName = hello.ServerName
			return cert, nil
		},
	}

	// accept the proxy CONNECT
	w.WriteHeader(http.StatusOK)

	// we need to hijack the client connection to pretend to be the server
	// from now on
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack connection: %v", err)
	}
	defer conn.Close()

	// connect to the server which our client originally wanted
	remoteConn, err := tls.Dial("tcp", r.Host, clientConf)
	if err != nil {
		return fmt.Errorf("failed to establish connection to server: %v", err)
	}
	defer remoteConn.Close()

	// establish ourselves to our client, presenting the certifi cate we signed
	// for the intented destination server
	clientConn := tls.Server(conn, serverConfig)
	if err := clientConn.Handshake(); err != nil {
		return fmt.Errorf("failed to hijack connection: %v", err)
	}
	defer clientConn.Close()

	rp := &handler.ReverseProxy{
		Director: httpsDirector,
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return remoteConn, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{}
				return d.DialContext(ctx, "tcp", addr)
			},
			// Proxy: func(r *http.Request) (*url.URL, error) {
			// 	url, err := url.Parse("")
			// 	if err != nil {
			// 		return nil, err
			// 	}
			// 	return http.ProxyURL(url)(r)
			// },
		},
	}

	ch := make(chan int)
	wc := &onCloseConn{clientConn, func() { ch <- 0 }}

	http.Serve(&oneShotListener{wc}, rp)
	<-ch
	return nil
}

type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}
