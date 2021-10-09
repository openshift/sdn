package metrics

// contains HTTP metric server for controller/master

import (
	"context"
	"net/http"
	"time"

	"k8s.io/klog/v2"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	shutdownTimeout = time.Millisecond * 50
	endpoint        = "/metrics"
	bindAddress     = "127.0.0.1:29100"
)

// StartServer registers prometheus metrics and starts HTTP server (non-blocking). Binding address maybe overridden by env variable.
func StartServer() *http.Server {
	register()
	handler := promhttp.InstrumentMetricHandler(registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux := http.NewServeMux()
	mux.Handle(endpoint, handler)
	server := &http.Server{Addr: bindAddress, Handler: mux}
	klog.Infof("Starting HTTP metrics server")

	go func() {
		if httpServerMessage := server.ListenAndServe(); httpServerMessage != nil && httpServerMessage != http.ErrServerClosed {
			klog.Errorf("HTTP metrics server ended with error: %v", httpServerMessage)
		}
		klog.Infof("HTTP metrics server finished")
	}()

	return server
}

// StopServer attempts to shutdown the HTTP server argument.
func StopServer(server *http.Server) {
	if server == nil {
		klog.Errorf("Stopping HTTP metric server failed due to nil pointer received")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if httpServerMessage := server.Shutdown(ctx); httpServerMessage != nil && httpServerMessage != http.ErrServerClosed {
		klog.Errorf("Shutting down HTTP metrics server caused error: %v", httpServerMessage)
	}
}
