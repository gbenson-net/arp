// Package arp queries the system ARP cache.
package arp

import (
	"net"
	"sync"
	"time"
)

type Resolver struct {
	// TTL is the minimum time between updates.
	TTL time.Duration

	hw2ip, ip2hw resolverTable
}

type resolverTable struct {
	mu       sync.Mutex
	table    Table
	deadline time.Time
}

// DefaultResolver is the resolver used by the package-level Lookup
// functions.
var DefaultResolver = &Resolver{TTL: 100 * time.Millisecond}

// LookupMAC returns the hardware address associated with the given
// IP address, as recorded in the system ARP cache.
func LookupMAC(ip net.IP) (net.HardwareAddr, error) {
	return DefaultResolver.LookupMAC(ip)
}

// LookupMAC returns the hardware address associated with the given
// IP address, as recorded in the system ARP cache.
func (r *Resolver) LookupMAC(ip net.IP) (net.HardwareAddr, error) {
	table, err := r.ip2hw.getTable(r.TTL, true, false)
	if err != nil {
		return nil, err
	}

	s, found := table[ip.String()]
	if !found {
		return nil, &notFoundError{ipAddrKind, ip}
	}

	return net.ParseMAC(s)
}

// LookupIP returns the IP address associated with the given hardware
// address, as recorded in the system ARP cache.
func LookupIP(hw net.HardwareAddr) (net.IP, error) {
	return DefaultResolver.LookupIP(hw)
}

// LookupIP returns the IP address associated with the given hardware
// address, as recorded in the system ARP cache.
func (r *Resolver) LookupIP(hw net.HardwareAddr) (net.IP, error) {
	table, err := r.hw2ip.getTable(r.TTL, false, true)
	if err != nil {
		return nil, err
	}

	s, found := table[hw.String()]
	if !found {
		return nil, &notFoundError{hwAddrKind, hw}
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, &net.AddrError{Err: "invalid IP address", Addr: s}
	}

	return ip, nil
}

func (r *resolverTable) getTable(
	ttl time.Duration,
	ip2hw, hw2ip bool,
) (Table, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Now().After(r.deadline) {
		t, err := readTable("/proc/net/arp", ip2hw, hw2ip)
		if err != nil {
			return nil, err
		}
		r.table = t
		r.deadline = time.Now().Add(ttl)
	}

	return r.table, nil
}
