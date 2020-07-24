package common

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog"
)

const (
	// defaultTTL is used if an invalid or zero TTL is provided.
	defaultTTL = 30 * time.Minute
)

type dnsValue struct {
	// Domain name to be queried to the DNS server.
	name string
	// All IPv4 addresses for a given domain name
	ips []net.IP
	// Time-to-live value from non-authoritative/cached name server for the domain
	ttl time.Duration
	// Channel to notify the goroutine to exit
	exit chan struct{}
}

type DNS struct {
	// Protects dnsMap operations
	lock sync.Mutex
	// Holds dns name and its corresponding information
	dnsMap map[string]*dnsValue
	// DNS resolvers
	nameservers []string
	// DNS port
	port string
	// Channel to notify the egress DNS component about changes in the ip address
	Updates chan string
}

func NewDNS(resolverConfigFile string) (*DNS, error) {
	config, err := dns.ClientConfigFromFile(resolverConfigFile)
	if err != nil || config == nil {
		return nil, fmt.Errorf("cannot initialize the resolver: %v", err)
	}

	return &DNS{
		dnsMap:      map[string]*dnsValue{},
		nameservers: filterIPv4Servers(config.Servers),
		port:        config.Port,
		Updates:     make(chan string),
	}, nil
}

func (d *DNS) Get(dns string) dnsValue {
	d.lock.Lock()
	defer d.lock.Unlock()

	data := dnsValue{}
	if res, ok := d.dnsMap[dns]; ok {
		data.ips = make([]net.IP, len(res.ips))
		copy(data.ips, res.ips)
		data.ttl = res.ttl
	}
	return data
}

func (d *DNS) Add(dns string) error {
	allErrs := utilvalidation.IsFullyQualifiedDomainName(field.NewPath("EgressDNS"), dns)
	if len(allErrs) > 0 {
		return fmt.Errorf("Ignoring rule for dnsName %s . Is not a valid domain name: %v", dns, allErrs.ToAggregate())
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	d.dnsMap[dns] = &dnsValue{
		name: dns,
		ips:  nil,
		ttl:  defaultTTL,
	}
	go d.sync(d.dnsMap[dns])
	return nil
}

//TODO add stop channel for delete
func (d *DNS) sync(dns *dnsValue) {
	// Don't wait for the first execution
	ttlTimer := time.Nanosecond
	klog.V(2).Infof("Starting sync for %s", dns.name)
	for {
		klog.V(2).Infof("waiting TTL for name: %s  TTL: %s", dns.name, ttlTimer)
		select {
		case <-time.After(ttlTimer):
			klog.V(2).Infof("Querying %s", dns.name)
			ips, ttl, err := d.getIPsAndMinTTL(dns.name)
			if err != nil {
				// If the first query failed for whatever reason set the time
				// to a second so that we don't do a DoS to the DNS server
				if ttlTimer == time.Nanosecond {
					ttlTimer = time.Second
				}
				klog.Warningf("Error querying %s, retrying again in %s", dns.name, ttlTimer)
			}
			klog.V(2).Infof("name: %s  TTL: %s", dns.name, ttl)

			if !ipsEqual(dns.ips, ips) {
				klog.Warningf("Updating IPs for", dns.name)
				timeBeforeUpdate := time.Now()
				d.Updates <- dns.name
				// Updating the channel is a blocking operation. Normally doesn't
				// take more than a fraction of milliseconds but compensate it anyway.
				ttlTimer = time.Now().Add(ttl).Sub(timeBeforeUpdate)
				continue
			}
			ttlTimer = ttl

		case <-dns.exit:
			break
		}
	}
	klog.V(2).Infof("Stopped sync for %s", dns.name)
}

func (d *DNS) Delete(dns string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.dnsMap[dns].exit <- struct{}{}
	delete(d.dnsMap, dns)
}

func (d *DNS) getIPsAndMinTTL(domain string) ([]net.IP, time.Duration, error) {
	ips := []net.IP{}
	ttlSet := false
	var ttlSeconds uint32

	for _, server := range d.nameservers {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

		dialServer := server
		if _, _, err := net.SplitHostPort(server); err != nil {
			dialServer = net.JoinHostPort(server, d.port)
		}
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		in, _, err := c.Exchange(msg, dialServer)
		if err != nil {
			return nil, defaultTTL, err
		}
		if in != nil && in.Rcode != dns.RcodeSuccess {
			return nil, defaultTTL, fmt.Errorf("failed to get a valid answer: %v", in)
		}

		if in != nil && len(in.Answer) > 0 {
			for _, a := range in.Answer {
				if !ttlSet || a.Header().Ttl < ttlSeconds {
					ttlSeconds = a.Header().Ttl
					ttlSet = true
				}

				switch t := a.(type) {
				case *dns.A:
					ips = append(ips, t.A)
				}
			}
		}
	}

	if !ttlSet || (len(ips) == 0) {
		return nil, defaultTTL, fmt.Errorf("IPv4 addr not found for domain: %q, nameservers: %v", domain, d.nameservers)
	}

	ttl, err := time.ParseDuration(fmt.Sprintf("%ds", ttlSeconds))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Invalid TTL value for domain: %q, err: %v, defaulting ttl=%s", domain, err, defaultTTL.String()))
		ttl = defaultTTL
	}
	if ttl == 0 {
		ttl = defaultTTL
	}

	return removeDuplicateIPs(ips), ttl, nil
}

func ipsEqual(oldips, newips []net.IP) bool {
	if len(oldips) != len(newips) {
		return false
	}

	for _, oldip := range oldips {
		found := false
		for _, newip := range newips {
			if oldip.Equal(newip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func filterIPv4Servers(servers []string) []string {
	ipv4Servers := []string{}
	for _, server := range servers {
		ipString := server
		if host, _, err := net.SplitHostPort(server); err == nil {
			ipString = host
		}

		if ip := net.ParseIP(ipString); ip != nil {
			if ip.To4() != nil {
				ipv4Servers = append(ipv4Servers, server)
			}
		}
	}

	return ipv4Servers
}

func removeDuplicateIPs(ips []net.IP) []net.IP {
	ipSet := sets.NewString()
	for _, ip := range ips {
		ipSet.Insert(ip.String())
	}

	uniqueIPs := []net.IP{}
	for _, str := range ipSet.List() {
		ip := net.ParseIP(str)
		if ip != nil {
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	return uniqueIPs
}
