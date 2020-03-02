package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lxt1045/gotun2socks"
	"github.com/lxt1045/gotun2socks/tun"
)

/*
 route add 0.0.0.0 mask 128.0.0.0 10.0.0.1  ����Ĭ��·��
 route add 128.0.0.0 mask 128.0.0.0 10.0.0.1
*/

func main() {
	var tunDevice string
	var tunAddr string
	var tunMask string
	var tunGW string
	var tunDNS string
	var localSocksAddr string
	var publicOnly bool
	var enableDnsCache bool
	flag.StringVar(&tunDevice, "tun-device", "tun0", "tun device name")
	flag.StringVar(&tunAddr, "tun-address", "10.0.0.2", "tun device address")
	flag.StringVar(&tunMask, "tun-mask", "255.255.255.0", "tun device netmask")
	flag.StringVar(&tunGW, "tun-gw", "10.0.0.1", "tun device gateway")
	flag.StringVar(&tunDNS, "tun-dns", "8.8.8.8,8.8.4.4", "tun dns servers")
	flag.StringVar(&localSocksAddr, "local-socks-addr", "127.0.0.1:1080", "local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.BoolVar(&enableDnsCache, "enable-dns-cache", false, "enable local dns cache if specified")

	var directAddr string
	flag.StringVar(&directAddr, "direct", "10.168.0.57", "direct addr")
	flag.Parse()

	directAddrs := strings.Split(directAddr, ",")

	dnsServers := strings.Split(tunDNS, ",")
	f, e := tun.OpenTunDevice(tunDevice, tunAddr, tunGW, tunMask, dnsServers)
	if e != nil {
		log.Fatal(e)
	}
	tun := gotun2socks.New(f, localSocksAddr, dnsServers, publicOnly, enableDnsCache)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-ch
		switch s {
		default:
			DeleteRoutes(directAddrs, tunGW)
			tun.Stop()
		}
	}()
	AddRoutes(directAddrs, tunGW)
	tun.Run()
}
