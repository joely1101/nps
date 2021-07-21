package client

import (
	"errors"
	"log"
	"net"
)

// NewMagicPacket allocates a new MagicPacket with the specified MAC.
type MagicPacket [114]byte

func newMagicPacket(macAddr string, password string) (packet MagicPacket, err error) {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return packet, err
	}

	if len(mac) != 6 {
		return packet, errors.New("invalid EUI-48 MAC address")
	}

	// write magic bytes to packet
	copy(packet[0:], []byte{255, 255, 255, 255, 255, 255})
	offset := 6

	for i := 0; i < 16; i++ {
		copy(packet[offset:], mac)
		offset += 6
	}
	if password != "" {
		if len(password) > 8 {
			password = password[0:8]
		}
		/*
			if password != "" {
				plen:=len(password)
				if plen > 6 {
					plen=6
				}
			}
		*/
		copy(packet[offset:], password[0:6])
	}

	return packet, nil
}

// Send writes the MagicPacket to the specified address on port 9.
func SendMagicPacket(mac string, password string, inf string) error {
	packet, err := newMagicPacket(mac, password)
	if err != nil {
		log.Printf("create packer fail %s ", err)
		return err
	}
	//send to 255.255.255.255:7
	raddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:7")
	if err != nil {
		log.Printf("udp address error %s ", err)
		return err
	}
	ifi, err := net.InterfaceByName(inf)
	if err != nil {
		log.Printf("NIC cannot open inf %s error %s ", inf, err)
		return err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		log.Printf("NIC cannot get addresses nic %s error %s ", inf, err)
		return err
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ip4 := *v
			if ip4.IP.To4() != nil {
				//fmt.Printf("ips=%s\n", ip4.IP.To4().String())
				ip := ip4.IP.To4().String() + ":0"
				laddr, err := net.ResolveUDPAddr("udp", ip)
				if err != nil {
					log.Printf("udp address %s error %s ", ip4.IP.To4().String()+":0", err)
					return err
				}
				conn, err := net.DialUDP("udp", laddr, raddr)
				if err != nil {
					log.Printf("DialUDP error %s ", err)
					return err
				}
				_, err = conn.Write(packet[:])
				if err != nil {
					conn.Close()
					log.Printf("Write data error %s ", err)
					return err
				}
				conn.Close()
			}
		}
	}
	/*
		laddr, err := net.ResolveUDPAddr("udp", src_ip)
		if err != nil {
			log.Printf("address %s error %s ", src_ip, err)
			return err
		}
		conn, err := net.DialUDP("udp", laddr, raddrs)
		if err != nil {
			log.Printf("DialUDP error %s ", err)
			return err
		}
		defer conn.Close()

		_, err = conn.Write(packet[:])
		if err != nil {
			log.Printf("Write data error %s ", err)
			return err
		}
	*/
	return nil
}
