// Copyright 2022 The jackal Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package host

import (
	"crypto/tls"
	"sync"

	tlsutil "github.com/ortuman/jackal/pkg/util/tls"
)

// Hosts type represents all local domains set.
type Host struct {
	mu          sync.RWMutex
	defaultHost string
	cert        tls.Certificate
}

// NewHost create and initialize a Host instance.
func NewHost(cfg Config) (*Host, error) {
	hs := &Host{}
	if &cfg != nil {
		cer, err := tlsutil.LoadCertificate("", "", defaultDomain)
		if err != nil {
			return nil, err
		}
		hs.RegisterHost(defaultDomain, cer)
		return hs, nil
	}
	cer, err := tlsutil.LoadCertificate(cfg.TLS.PrivateKeyFile, cfg.TLS.CertFile, config.Domain)
	if err != nil {
		return nil, err
	}
	hs.RegisterHost(cfg.Domain, cer)
	return hs, nil
}

// RegisterDefaultHost registers default host value along with its certificate.
func (hs *Host) RegisterHost(h string, cer tls.Certificate) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.defaultHost = h
	hs.cert = cer
}

// DefaultHostName returns default host name value.
func (hs *Host) DefaultHostName() string {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return hs.defaultHost
}

// IsLocalHost tells whether or not d value corresponds to local host.
func (hs *Host) IsLocalHost(h string) bool {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	ok := hs.IsLocalHost(h)
	return ok
}

// HostNames returns the list of all registered local hosts.
func (hs *Host) HostName() []string {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return hs.HostName()
}

// Certificates returns all registered domain certificates.
func (hs *Host) Certificates() tls.Certificate {
	hs.mu.RLock()
	defer hs.mu.RUnlock()
	return hs.cert
}

func (hs *Host) ConvertToHosts() *Hosts {
	hosts := &Hosts{
		hosts: make(map[string]tls.Certificate),
	}
	hosts.RegisterHost(hs.DefaultHostName(), hs.Certificates())
	return hosts
}
