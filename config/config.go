package config

import (
        "net"
        "strings"

        "gopkg.in/ini.v1"
)

type Config struct {
        SSHPort              string
        HostKeyFile          string
        ForceCommand         string
        ForceOnExitCommand   string
        RealIPFallback       string
        ProxyProtocolEnabled bool
        ProxyAllowedIPs      []net.IPNet
        NickServAPI          struct {
                URL                     string
                RegisterURL             string // New field for registration endpoint
                Token                   string
                AllowRegistrationOnFail bool // New field for the toggle
        }
}

func Load(path string) (*Config, error) {
        cfgFile, err := ini.Load(path)
        if err != nil {
                return nil, err
        }

        cfg := &Config{}

        serverSection := cfgFile.Section("server")
        cfg.SSHPort = serverSection.Key("port").MustString("2222")
        cfg.HostKeyFile = serverSection.Key("host_key_file").String()
        cfg.ForceCommand = serverSection.Key("force_command").String()
        cfg.ForceOnExitCommand = serverSection.Key("forceonexit").String()
        cfg.RealIPFallback = serverSection.Key("real_ip_fallback").MustString("127.0.0.1")
        cfg.ProxyProtocolEnabled = serverSection.Key("proxy_protocol_enabled").MustBool(false)

        // Parse proxy_allowed_ips
        proxyAllowedIPsStr := serverSection.Key("proxy_allowed_ips").String()
        if proxyAllowedIPsStr != "" {
                for _, ipStr := range strings.Split(proxyAllowedIPsStr, ",") {
                        ipStr = strings.TrimSpace(ipStr)
                        if ipStr == "" {
                                continue
                        }
                        _, ipNet, err := net.ParseCIDR(ipStr)
                        if err != nil {
                                // If it's not a CIDR, try parsing it as a single IP
                                ip := net.ParseIP(ipStr)
                                if ip == nil {
                                        return nil, err // Or handle the error as appropriate
                                }
                                // Create a /32 for IPv4 or /128 for IPv6 for single IPs
                                if ip.To4() != nil {
                                        _, ipNet, _ = net.ParseCIDR(ipStr + "/32")
                                } else {
                                        _, ipNet, _ = net.ParseCIDR(ipStr + "/128")
                                }
                        }
                        cfg.ProxyAllowedIPs = append(cfg.ProxyAllowedIPs, *ipNet)
                }
        }

        nickservSection := cfgFile.Section("nickserv")
        cfg.NickServAPI.URL = nickservSection.Key("api_url").String()
        cfg.NickServAPI.RegisterURL = nickservSection.Key("register_api_url").String()
        cfg.NickServAPI.Token = nickservSection.Key("api_token").String()
        // Load the new setting from the [nickserv] section
        cfg.NickServAPI.AllowRegistrationOnFail = nickservSection.Key("allow_registration_on_fail").MustBool(false)

        return cfg, nil
}