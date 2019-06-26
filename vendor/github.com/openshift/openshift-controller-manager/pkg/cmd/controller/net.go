package controller

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

// ListenAndServeTLS starts a server that listens on the provided TCP mode (as supported
// by net.Listen).
func ListenAndServeTLS(srv *http.Server, network string, certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		config = srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	return srv.Serve(tlsListener)
}

// GetCertificateFunc returns a function that can be used in tls.Config#GetCertificate
// Returns nil if len(certs) == 0
func GetCertificateFunc(certs map[string]*tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(certs) == 0 {
		return nil
	}
	// Replica of tls.Config#getCertificate logic
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if clientHello == nil {
			return nil, nil
		}

		name := clientHello.ServerName
		name = strings.ToLower(name)
		name = strings.TrimRight(name, ".")
		for _, candidate := range HostnameMatchSpecCandidates(name) {
			if cert, ok := certs[candidate]; ok {
				return cert, nil
			}
		}
		return nil, nil
	}
}

// HostnameMatchSpecCandidates returns a list of match specs that would match the provided hostname
// Returns nil if len(hostname) == 0
func HostnameMatchSpecCandidates(hostname string) []string {
	if len(hostname) == 0 {
		return nil
	}

	// Exact match has priority
	candidates := []string{hostname}

	// Replace successive labels in the name with wildcards, to require an exact match on number of
	// path segments, because certificates cannot wildcard multiple levels of subdomains
	//
	// This is primarily to be consistent with tls.Config#getCertificate implementation
	//
	// It using a cert signed for *.foo.example.com and *.bar.example.com by specifying the name *.*.example.com
	labels := strings.Split(hostname, ".")
	for i := range labels {
		labels[i] = "*"
		candidates = append(candidates, strings.Join(labels, "."))
	}
	return candidates
}
