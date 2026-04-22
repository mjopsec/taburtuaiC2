package main

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanResult holds the result for a single host:port probe.
type ScanResult struct {
	Host    string
	Port    int
	Open    bool
	Banner  string
	Latency time.Duration
}

// NetScanOpts controls scanner behaviour.
type NetScanOpts struct {
	Targets  []string // CIDR or individual IPs
	Ports    []int    // port numbers to probe
	Timeout  time.Duration
	Workers  int
	GrabBanner bool
}

// RunNetScan performs a concurrent TCP port scan.
func RunNetScan(opts NetScanOpts) ([]ScanResult, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 500 * time.Millisecond
	}
	if opts.Workers == 0 {
		opts.Workers = 200
	}
	if len(opts.Ports) == 0 {
		opts.Ports = commonPorts()
	}

	hosts, err := expandTargets(opts.Targets)
	if err != nil {
		return nil, err
	}

	type job struct {
		host string
		port int
	}

	jobs := make(chan job, opts.Workers*2)
	results := make(chan ScanResult, opts.Workers*2)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- probePort(j.host, j.port, opts.Timeout, opts.GrabBanner)
			}
		}()
	}

	go func() {
		for _, host := range hosts {
			for _, port := range opts.Ports {
				jobs <- job{host, port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var out []ScanResult
	for r := range results {
		if r.Open {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

func probePort(host string, port int, timeout time.Duration, grab bool) ScanResult {
	r := ScanResult{Host: host, Port: port}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	r.Latency = time.Since(start)
	if err != nil {
		return r
	}
	r.Open = true
	if grab {
		conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			r.Banner = strings.TrimSpace(string(buf[:n]))
		}
	}
	conn.Close()
	return r
}

func expandTargets(targets []string) ([]string, error) {
	var hosts []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if strings.Contains(t, "/") {
			ips, err := cidrHosts(t)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", t, err)
			}
			hosts = append(hosts, ips...)
		} else {
			hosts = append(hosts, t)
		}
	}
	return hosts, nil
}

func cidrHosts(cidr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for ip := cloneIP(network.IP); network.Contains(ip); incrementIP(ip) {
		// skip network and broadcast
		if !isNetworkOrBroadcast(ip, network) {
			hosts = append(hosts, ip.String())
		}
	}
	return hosts, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isNetworkOrBroadcast(ip net.IP, n *net.IPNet) bool {
	// network address: all host bits zero
	network := n.IP
	if ip.Equal(network) {
		return true
	}
	// broadcast: all host bits one
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^n.Mask[i]
	}
	return ip.Equal(broadcast)
}

func commonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143,
		389, 443, 445, 587, 636, 1433, 1521, 3306, 3389,
		5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017,
	}
}

// ARPScan returns ARP table entries visible to the OS (cross-platform via `arp -a`).
func ARPScan() (string, error) {
	out, err := exec.Command("arp", "-a").CombinedOutput()
	return string(out), err
}
