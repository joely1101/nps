package client

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	nps_mux "ehang.io/nps-mux"

	"github.com/astaxie/beego/logs"
	"github.com/xtaci/kcp-go"

	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/config"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/file"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/joely1101/arp"
	reuse "github.com/libp2p/go-reuseport"
)

type TRPClient struct {
	svrAddr        string
	bridgeConnType string
	proxyUrl       string
	vKey           string
	p2pAddr        map[string]string
	tunnel         *nps_mux.Mux
	signal         *conn.Conn
	ticker         *time.Ticker
	cnf            *config.Config
	disconnectTime int
	once           sync.Once
	Scaniface      string
}

//new client
func NewRPClient(svraddr string, vKey string, bridgeConnType string, proxyUrl string, cnf *config.Config, disconnectTime int) *TRPClient {
	return &TRPClient{
		svrAddr:        svraddr,
		p2pAddr:        make(map[string]string, 0),
		vKey:           vKey,
		bridgeConnType: bridgeConnType,
		proxyUrl:       proxyUrl,
		cnf:            cnf,
		disconnectTime: disconnectTime,
		once:           sync.Once{},
	}
}

var NowStatus int
var CloseClient bool

//start
func (s *TRPClient) Start() {
	CloseClient = false
retry:
	if CloseClient {
		return
	}
	NowStatus = 0
	c, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_MAIN, s.proxyUrl)
	if err != nil {
		logs.Error("The connection server failed and will be reconnected in five seconds, error", err.Error())
		time.Sleep(time.Second * 5)
		goto retry
	}
	if c == nil {
		logs.Error("Error data from server, and will be reconnected in five seconds")
		time.Sleep(time.Second * 5)
		goto retry
	}
	logs.Info("Successful connection with server %s", s.svrAddr)
	//monitor the connection
	go s.ping()
	s.signal = c
	//start a channel connection
	go s.newChan()
	//start health check if the it's open
	if s.cnf != nil && len(s.cnf.Healths) > 0 {
		go heathCheck(s.cnf.Healths, s.signal)
	}
	NowStatus = 1
	if s.Scaniface != "" {
		go s.arpscan()
	} else {
		logs.Warn("ARP monitor disabled")
	}
	//msg connection, eg udp
	s.handleMain()
}
func processCmdFromserver(s *TRPClient, cmdall string) {
	//sendmagic
	//format: string_cmd:
	//logs.Warn("processCmdFromserver  msg %s",cmdall)
	argv := strings.SplitN(cmdall, ":", 2)
	cmd := argv[0]
	if cmd == "" {
		logs.Warn("invlaid command: %s", cmdall)
		return
	}
	if argv[1] == "" {
		logs.Warn("invlaid paramter %s", cmdall)
		return
	}
	param := argv[1]
	switch cmd {
	//format wol:00:11:22:33:44:55 00:11:22:33:44:52 ...
	case "wol":
		param2 := strings.Split(param, " ")
		for i := range param2 {
			logs.Warn("Send magic packet  to %s", param2[i])
			err := SendMagicPacket(param2[i], "", s.Scaniface)
			if err == nil {
				logs.Warn("Send magic packet  to %s success", param2[i])
			} else {
				logs.Warn("Send magic packet  to %s fail", param2[i])
			}
		}
	default:
		logs.Warn("Unknow command %s", cmd)
	}

}

//handle main connection
func (s *TRPClient) handleMain() {

	for {
		flags, err := s.signal.ReadFlag()
		if err != nil {
			logs.Error("Accept server data error %s, end this service", err.Error())
			break
		}
		switch flags {
		case common.NEW_UDP_CONN:
			//read server udp addr and password
			if lAddr, err := s.signal.GetShortLenContent(); err != nil {
				logs.Warn(err)
				return
			} else if pwd, err := s.signal.GetShortLenContent(); err == nil {
				var localAddr string
				//The local port remains unchanged for a certain period of time
				if v, ok := s.p2pAddr[crypt.Md5(string(pwd)+strconv.Itoa(int(time.Now().Unix()/100)))]; !ok {
					tmpConn, err := common.GetLocalUdpAddr()
					if err != nil {
						logs.Error(err)
						return
					}
					localAddr = tmpConn.LocalAddr().String()
				} else {
					localAddr = v
				}
				go s.newUdpConn(localAddr, string(lAddr), string(pwd))
			}
		case common.STRING_COMMAND:
			msg, err := s.signal.GetShortLenContent()
			//logs.Warn("WOL_COMMAND  msg %s",msg)
			if err != nil {
				logs.Warn(err)
				return
			}
			processCmdFromserver(s, string(msg))

		}
	}
	s.Close()
}

func (s *TRPClient) newUdpConn(localAddr, rAddr string, md5Password string) {
	var localConn net.PacketConn
	var err error
	var remoteAddress string
	if remoteAddress, localConn, err = handleP2PUdp(localAddr, rAddr, md5Password, common.WORK_P2P_PROVIDER); err != nil {
		logs.Error(err)
		return
	}
	l, err := kcp.ServeConn(nil, 150, 3, localConn)
	if err != nil {
		logs.Error(err)
		return
	}
	logs.Trace("start local p2p udp listen, local address", localConn.LocalAddr().String())
	for {
		udpTunnel, err := l.AcceptKCP()
		if err != nil {
			logs.Error(err)
			l.Close()
			return
		}
		if udpTunnel.RemoteAddr().String() == string(remoteAddress) {
			conn.SetUdpSession(udpTunnel)
			logs.Info("successful connection with client ,address %s", udpTunnel.RemoteAddr().String())
			//read link info from remote
			conn.Accept(nps_mux.NewMux(udpTunnel, s.bridgeConnType, s.disconnectTime), func(c net.Conn) {
				go s.handleChan(c)
			})
			break
		}
	}
}

//pmux tunnel
func (s *TRPClient) newChan() {
	tunnel, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_CHAN, s.proxyUrl)
	if err != nil {
		logs.Error("connect to ", s.svrAddr, "error:", err)
		return
	}
	s.tunnel = nps_mux.NewMux(tunnel.Conn, s.bridgeConnType, s.disconnectTime)
	for {
		src, err := s.tunnel.Accept()
		if err != nil {
			logs.Warn(err)
			s.Close()
			break
		}
		go s.handleChan(src)
	}
}

func (s *TRPClient) handleChan(src net.Conn) {
	lk, err := conn.NewConn(src).GetLinkInfo()
	if err != nil || lk == nil {
		src.Close()
		logs.Error("get connection info from server error ", err)
		return
	}
	//host for target processing
	lk.Host = common.FormatAddress(lk.Host)
	//if Conn type is http, read the request and log
	if lk.ConnType == "http" {
		if targetConn, err := net.DialTimeout(common.CONN_TCP, lk.Host, lk.Option.Timeout); err != nil {
			logs.Warn("connect to %s error %s", lk.Host, err.Error())
			src.Close()
		} else {
			srcConn := conn.GetConn(src, lk.Crypt, lk.Compress, nil, false)
			go func() {
				common.CopyBuffer(srcConn, targetConn)
				srcConn.Close()
				targetConn.Close()
			}()
			for {
				if r, err := http.ReadRequest(bufio.NewReader(srcConn)); err != nil {
					srcConn.Close()
					targetConn.Close()
					break
				} else {
					logs.Trace("http request, method %s, host %s, url %s, remote address %s", r.Method, r.Host, r.URL.Path, r.RemoteAddr)
					r.Write(targetConn)
				}
			}
		}
		return
	}
	if lk.ConnType == "udp5" {
		logs.Trace("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		s.handleUdp(src)
	}
	//connect to target if conn type is tcp or udp
	if targetConn, err := net.DialTimeout(lk.ConnType, lk.Host, lk.Option.Timeout); err != nil {
		logs.Warn("connect to %s error %s", lk.Host, err.Error())
		src.Close()
	} else {
		logs.Warn("new %s connection with the goal of %s, remote address:%s", lk.ConnType, lk.Host, lk.RemoteAddr)
		conn.CopyWaitGroup(src, targetConn, lk.Crypt, lk.Compress, nil, nil, false, nil)
	}
}

func (s *TRPClient) handleUdp(serverConn net.Conn) {
	// bind a local udp port
	local, err := net.ListenUDP("udp", nil)
	defer serverConn.Close()
	if err != nil {
		logs.Error("bind local udp port error ", err.Error())
		return
	}
	defer local.Close()
	go func() {
		defer serverConn.Close()
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		for {
			n, raddr, err := local.ReadFrom(b)
			if err != nil {
				logs.Error("read data from remote server error", err.Error())
			}
			buf := bytes.Buffer{}
			dgram := common.NewUDPDatagram(common.NewUDPHeader(0, 0, common.ToSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			b, err := conn.GetLenBytes(buf.Bytes())
			if err != nil {
				logs.Warn("get len bytes error", err.Error())
				continue
			}
			if _, err := serverConn.Write(b); err != nil {
				logs.Error("write data to remote  error", err.Error())
				return
			}
		}
	}()
	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	for {
		n, err := serverConn.Read(b)
		if err != nil {
			logs.Error("read udp data from server error ", err.Error())
			return
		}

		udpData, err := common.ReadUDPDatagram(bytes.NewReader(b[:n]))
		if err != nil {
			logs.Error("unpack data error", err.Error())
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", udpData.Header.Addr.String())
		if err != nil {
			logs.Error("build remote addr err", err.Error())
			continue // drop silently
		}
		_, err = local.WriteTo(udpData.Data, raddr)
		if err != nil {
			logs.Error("write data to remote ", raddr.String(), "error", err.Error())
			return
		}
	}
}

// Whether the monitor channel is closed
func (s *TRPClient) ping() {
	s.ticker = time.NewTicker(time.Second * 5)
loop:
	for {
		select {
		case <-s.ticker.C:
			if s.tunnel != nil && s.tunnel.IsClose {
				s.Close()
				break loop
			}
		}
	}
}

func (s *TRPClient) Close() {
	s.once.Do(s.closing)
}

func (s *TRPClient) closing() {
	CloseClient = true
	NowStatus = 0
	if s.tunnel != nil {
		_ = s.tunnel.Close()
	}
	if s.signal != nil {
		_ = s.signal.Close()
	}
	if s.ticker != nil {
		s.ticker.Stop()
	}

}

var (
	dhcphostname = make(map[string]string)
)

func parsePacket(data []byte) *layers.DHCPv4 {
	packet := gopacket.NewPacket(data, layers.LayerTypeDHCPv4, gopacket.Default)
	//packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	//dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)

	if dhcpLayer == nil {
		fmt.Printf("dhcpLayer null")
		return nil
	}
	return dhcpLayer.(*layers.DHCPv4)
}

var hostname_monitor_running bool = false

func hostname_monitor() {
	if hostname_monitor_running {
		return
	}
	logs.Warn("starting dhcp packet monitor")
	pc, err := reuse.ListenPacket("udp", ":67")
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}
	//dhcphostname = make(map[string]string)
	buffer := make([]byte, 1600)
	defer pc.Close()
	hostname_monitor_running = true
	for {
		if CloseClient {
			return
		}
		hostname := ""
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			return
		}
		pkt := parsePacket(buffer)
		if pkt == nil {
			continue
		}

		//[layers.DHCPOptHostname]
		hostname = ""
		for _, o := range pkt.Options {
			if o.Type == layers.DHCPOptHostname {
				hostname = string(o.Data)
				break
			}
		}
		if hostname != "" {
			dhcphostname[pkt.ClientHWAddr.String()] = hostname
			fmt.Printf("name= %s mac=%s\n", hostname, pkt.ClientHWAddr)
		} else {
			fmt.Printf("name unknow mac=%s\n", pkt.ClientHWAddr)
		}
		fmt.Printf("packet-received: bytes=%d from=%s\n", n, addr.String())
	}
	hostname_monitor_running = false
}

//var arpChannel chan arp.MACEntry
func (s *TRPClient) arpscan() {
	arp.Debug = false
	NIC := s.Scaniface
	//var err error
	HomeLAN, HostMAC, err := getNICInfo(NIC)
	if err != nil {
		log.Print("error cannot get host ip and mac ", err)
		return

	}
	HostIP := HomeLAN.IP
	bits, _ := HomeLAN.Mask.Size()
	if bits < 24 {
		HomeLAN.Mask = net.CIDRMask(24, 32)
		logs.Warn("Subnet to large, use 24 bits only")
	}
	//log.Print(" Home LAN: ", HomeLAN)
	HomeLAN.IP = HostIP.Mask(HomeLAN.Mask)
	//HomeLAN := net.IPNet{IP: net.IPv4(HostIP[0], HostIP[1], HostIP[2], 0), Mask: net.CIDRMask(mask, 32)}
	//HomeRouterIP := net.ParseIP(*defaultGw)
	//if HomeRouterIP == nil {
	//	HomeRouterIP, err = getLinuxDefaultGateway()
	//}
	HomeRouterIP, err := getLinuxDefaultGateway()
	if err != nil {
		log.Fatal("cannot get default gateway ", err)
	}
	logs.Info("Scan on %s IP %s/%s gateway:%s ", NIC, HostIP.String(), net.IP(HomeLAN.Mask).String(), net.IP(HomeRouterIP).String())

retry:
	if CloseClient {
		return
	}
	NowStatus = 0
	ct, err := NewConn(s.bridgeConnType, s.vKey, s.svrAddr, common.WORK_CMD_RPC, s.proxyUrl)
	logs.Info("new Control session for RPC ...")
	if err != nil {
		logs.Error("The connection server failed and will be reconnected in five seconds, error", err.Error())
		time.Sleep(time.Second * 5)
		goto retry
	}
	if ct == nil {
		logs.Error("Error data from server, and will be reconnected in five seconds")
		time.Sleep(time.Second * 5)
		goto retry
	}

	ctx, cancel := context.WithCancel(context.Background())
	//ctx, _ := context.WithCancel(context.Background())
	config := arp.Config{
		NIC:     NIC,
		HostMAC: HostMAC, HostIP: HostIP,
		RouterIP: HomeRouterIP, HomeLAN: HomeLAN,
		ProbeInterval:           time.Second * 60,
		FullNetworkScanInterval: time.Minute * 5,
		PurgeDeadline:           0}
	c, err := arp.New(config)
	if err != nil {
		log.Fatal("error connection to websocket server", err)
	}
	go c.ListenAndServe(ctx)
	go hostname_monitor()
	arpChannel := make(chan arp.MACEntry, 16)
	c.AddNotificationChannel(arpChannel)
	go arpNotification(arpChannel, ct, HomeLAN)
	//wait if client if stop
	for {
		if CloseClient {
			break
		}
		time.Sleep(time.Second * 5)
	}
	close(arpChannel)
	cancel()
	c.Close()
}

type portlist struct {
	ports []int
}

func tcpscanThenSend(entry file.ARPEntry, ports portlist, signal *conn.Conn) {
	ipstr := entry.IP
	scanport := []int{22, 23, 80, 443, 8080}
	//scan tcp port 21,22,80,443
	for _, num := range scanport {
		address := fmt.Sprintf("%s:%d", ipstr, num)

		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			// either the port is filtered or closed
			continue
		}
		conn.Close()
		ports.ports = append(ports.ports, num)
	}
	nb := new(ProbeNetbios)
	entry.Name = nb.GetnamebyIP(ipstr)
	if entry.Name == "" {
		value, ok := dhcphostname[entry.MAC]
		if ok {
			entry.Name = value
		} else {
			entry.Name = "N/A"
		}
	}
	entry.Openport = ports.ports
	jsondata, _ := json.Marshal(entry)
	signal.Write([]byte(common.STRING_COMMAND))
	alldata := "macentry:" + string(jsondata)
	signal.WriteLenContent([]byte(alldata))
}

func arpNotification(arpChannel chan arp.MACEntry, signal *conn.Conn, lan net.IPNet) {
	openportlist := make(map[string]portlist)
	for {
		select {
		case MACEntry, more := <-arpChannel:
			if !more {
				return
			}
			if !lan.Contains(MACEntry.IP()) {
				continue
			}
			ipstr := MACEntry.IP().String()
			if MACEntry.Online {
				v, found := openportlist[ipstr]
				if !found {
					Entry := file.ARPEntry{
						MAC:    MACEntry.MAC.String(),
						IP:     MACEntry.IP().String(),
						Name:   "N/A",
						Online: MACEntry.Online}
					go tcpscanThenSend(Entry, v, signal)
					continue
				} else {
					//logs.Info("%s not update %v\n",ipstr,v)
				}
			} else {
				delete(openportlist, ipstr)
				//logs.Info("delete %s port list\n",ipstr)
			}
			Entry := file.ARPEntry{
				MAC:    MACEntry.MAC.String(),
				IP:     MACEntry.IP().String(),
				Name:   "N/A",
				Online: MACEntry.Online}
			value, ok := dhcphostname[Entry.MAC]
			if ok {
				Entry.Name = value
			}
			jsondata, _ := json.Marshal(Entry)
			//fmt.Println(string(jsondata))
			//fmt.Println("write command")
			signal.Write([]byte(common.STRING_COMMAND))
			alldata := "macentry:" + string(jsondata)
			//fmt.Println(alldata)
			signal.WriteLenContent([]byte(alldata))
			//fmt.Println(string(jsondata))
			//log.Printf("xxxx notification got ARP MACEntry for %s", MACEntry)
		}
	}
}

/*
func getMAC(c *arp.Handler, text string) (arp.MACEntry, error) {
	if len(text) <= 3 {
		return arp.MACEntry{}, fmt.Errorf("Invalid MAC")
	}
	mac, err := net.ParseMAC(text[2:])
	if err != nil {
		return arp.MACEntry{}, fmt.Errorf("Invalid MAC: %w", err)
	}

	entry, found := c.FindMAC(mac)
	if !found {
		return arp.MACEntry{}, fmt.Errorf("MAC not found")
	}
	return entry, nil
}
*/
func getNICInfo(nic string) (ip net.IPNet, mac net.HardwareAddr, err error) {

	//all, err := net.Interfaces()
	//for _, v := range all {
	//log.Print("interface name ", v.Name, v.HardwareAddr.String())
	//}
	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		log.Printf("NIC cannot open nic %s error %s ", nic, err)
		return ip, mac, err
	}

	mac = ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil {
		log.Printf("NIC cannot get addresses nic %s error %s ", nic, err)
		return ip, mac, err
	}

	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ip4 := *v
			if ip4.IP.To4() != nil {
				//fmt.Printf("%v : %s [%v/%v]\n", ifi.Name, v, v.IP, v.Mask)
				ip = *v
				break
			}

		}
	}
	/*
		if ip == nil || ip.Equal(net.IPv4zero) {
			err = fmt.Errorf("NIC cannot find IPv4 address list - is %s up?", nic)
			log.Print(err)
			return ip, mac, err
		}
	*/
	//log.Printf("NIC successfull acquired host nic information mac=%s ip=%v", mac, ip)
	return ip, mac, err
}

const (
	netfile = "/proc/net/route"
	line    = 1    // line containing the gateway addr. (first line: 0)
	sep     = "\t" // field separator
	field   = 2    // field containing hex gateway address (first field: 0)
)

// NICDefaultGateway read the default gateway from linux route file
//
// file: /proc/net/route file:
//   Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
//   eth0    00000000    C900A8C0    0003    0   0   100 00000000    0   00
//   eth0    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
//
func getLinuxDefaultGateway() (gw net.IP, err error) {

	file, err := os.Open(netfile)
	if err != nil {
		log.Print("NIC cannot open route file ", err)
		return net.IPv4zero, err
	}
	defer file.Close()

	ipd32 := net.IP{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// jump to line containing the gateway address
		for i := 0; i < line; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		gatewayHex := "0x" + tokens[field]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		//fmt.Printf("NIC default gateway is %T --> %[1]v\n", ipd32)

		// format net.IP to dotted ipV4 string
		//ip := net.IP(ipd32).String()
		//fmt.Printf("%T --> %[1]v\n", ip)

		// exit scanner
		break
	}
	return ipd32, nil
}
