package main

import (
	"flag"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lxt1045/gotun2socks"
	"github.com/lxt1045/gotun2socks/tun"

	"github.com/lxt1045/go-shadowsocks2/core"
	"github.com/lxt1045/go-shadowsocks2/socks"
)

/*
 route add 0.0.0.0 mask 128.0.0.0 10.0.0.1  ����Ĭ��·��
 route add 128.0.0.0 mask 128.0.0.0 10.0.0.1

 可以使用以下命令启动：
 C:\project\src\github.com\lxt1045\gotun2socks\bin\gotun2socks\gotun2socks.exe -direct 172.16.*.*,10.*.*.*,192.168.*.* -local-socks-addr ":1081" -c  ss://AEAD_CHACHA20_POLY1305:123456@jumpserver.xwfintech.com:38488
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
	flag.StringVar(&localSocksAddr, "local-socks-addr", ":1081", "local SOCKS proxy address")
	flag.BoolVar(&publicOnly, "public-only", false, "only forward packets with public address destination")
	flag.BoolVar(&enableDnsCache, "enable-dns-cache", false, "enable local dns cache if specified")

	var directAddr string
	flag.StringVar(&directAddr, "direct", "172.16.1.93,172.16.1.82,10.168.0.100", "direct addr")

	//socks的

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")

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

	if flags.Client != "" {
		socksConn(localSocksAddr)
	}
	tun.Run()
}

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var flags struct {
	Client   string
	Socks    string
	UDPSocks bool
}

func socksConn(localSocksAddr string) {

	/*
		ps -aux|grep "./ss2"
		./ss2 -s ss://AEAD_CHACHA20_POLY1305:123456@:38488 -verbose >/dev/null 2>&1 &
		./ss2 -c ss://AES-256-CFB:1tBzXtDJiuEgBIda@proxy.xwfintech.com:38388 -s ss://AEAD_CHACHA20_POLY1305:123456@:38489 -verbose > /dev/null 2>&1 &
	*/

	flags.Socks = localSocksAddr

	flags.Client = "ss://AEAD_CHACHA20_POLY1305:123456@jumpserver.xwfintech.com:38488"

	if flags.Client == "" {
		flag.Usage()
		return
	}

	var key []byte

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := ""
		password := ""
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
			if flags.UDPSocks {
				go udpSocksLocal(flags.Socks, udpAddr, ciph.PacketConn)
			}
		}
	}

}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
