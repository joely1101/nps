package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

type NetbiosInfo struct {
	statusRecv  time.Time
	nameSent    time.Time
	nameRecv    time.Time
	statusReply NetbiosReplyStatus
	nameReply   NetbiosReplyStatus
}

type ProbeNetbios struct {
	socket  net.PacketConn
	replies map[string]*NetbiosInfo
}

type NetbiosReplyHeader struct {
	XID             uint16
	Flags           uint16
	QuestionCount   uint16
	AnswerCount     uint16
	AuthCount       uint16
	AdditionalCount uint16
	QuestionName    [34]byte
	RecordType      uint16
	RecordClass     uint16
	RecordTTL       uint32
	RecordLength    uint16
}

type NetbiosReplyName struct {
	Name [15]byte
	Type uint8
	Flag uint16
}

type NetbiosReplyAddress struct {
	Flag    uint16
	Address [4]uint8
}

type NetbiosReplyStatus struct {
	Header    NetbiosReplyHeader
	HostName  [15]byte
	UserName  [15]byte
	Names     []NetbiosReplyName
	Addresses []NetbiosReplyAddress
	HWAddr    string
}

func TrimName(name string) string {
	return strings.TrimSpace(strings.Replace(name, "\x00", "", -1))
}

func (this *ProbeNetbios) SendRequest(ip string, req []byte) {
	addr, aerr := net.ResolveUDPAddr("udp", ip+":137")
	if aerr != nil {
		log.Printf("probe %s failed to resolve %s (%s)", this, ip, aerr)
		return
	}

	// Retry in case of network buffer congestion
	wcnt := 0
	for wcnt = 0; wcnt < 5; wcnt++ {
		_, werr := this.socket.WriteTo(req, addr)
		if werr != nil {
			log.Printf("probe %s [%d/%d] failed to send to %s (%s)", this, wcnt+1, 5, ip, werr)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}

	// Were we able to send it eventually?
	if wcnt == 5 {
		log.Printf("probe %s [%d/%d] gave up sending to %s", this, wcnt, 5, ip)
	}
}

func (this *ProbeNetbios) SendStatusRequest(ip string) {
	// log.Printf("probe %s is sending a status request to %s", this, ip)
	this.SendRequest(ip, this.CreateStatusRequest())
}

func (this *ProbeNetbios) SendNameRequest(ip string) {
	sreply := this.replies[ip].statusReply
	name := TrimName(string(sreply.HostName[:]))
	this.SendRequest(ip, this.CreateNameRequest(name))
}



func (this *ProbeNetbios) EncodeNetbiosName(name [16]byte) [32]byte {
	encoded := [32]byte{}

	for i := 0; i < 16; i++ {
		if name[i] == 0 {
			encoded[(i*2)+0] = 'C'
			encoded[(i*2)+1] = 'A'
		} else {
			encoded[(i*2)+0] = byte((name[i] / 16) + 0x41)
			encoded[(i*2)+1] = byte((name[i] % 16) + 0x41)
		}
	}

	return encoded
}

func (this *ProbeNetbios) DecodeNetbiosName(name [32]byte) [16]byte {
	decoded := [16]byte{}

	for i := 0; i < 16; i++ {
		if name[(i*2)+0] == 'C' && name[(i*2)+1] == 'A' {
			decoded[i] = 0
		} else {
			decoded[i] = ((name[(i*2)+0] * 16) - 0x41) + (name[(i*2)+1] - 0x41)
		}
	}
	return decoded
}

func (this *ProbeNetbios) ParseReply(buff []byte) NetbiosReplyStatus {

	resp := NetbiosReplyStatus{}
	temp := bytes.NewBuffer(buff)

	binary.Read(temp, binary.BigEndian, &resp.Header)

	if resp.Header.QuestionCount != 0 {
		return resp
	}

	if resp.Header.AnswerCount == 0 {
		return resp
	}

	// Names
	if resp.Header.RecordType == 0x21 {
		var rcnt uint8
		var ridx uint8
		binary.Read(temp, binary.BigEndian, &rcnt)

		for ridx = 0; ridx < rcnt; ridx++ {
			name := NetbiosReplyName{}
			binary.Read(temp, binary.BigEndian, &name)
			resp.Names = append(resp.Names, name)

			if name.Type == 0x20 {
				resp.HostName = name.Name
			}

			if name.Type == 0x03 {
				resp.UserName = name.Name
			}
		}

		var hwbytes [6]uint8
		binary.Read(temp, binary.BigEndian, &hwbytes)
		resp.HWAddr = fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			hwbytes[0], hwbytes[1], hwbytes[2], hwbytes[3], hwbytes[4], hwbytes[5],
		)
		return resp
	}

	// Addresses
	if resp.Header.RecordType == 0x20 {
		var ridx uint16
		for ridx = 0; ridx < (resp.Header.RecordLength / 6); ridx++ {
			addr := NetbiosReplyAddress{}
			binary.Read(temp, binary.BigEndian, &addr)
			resp.Addresses = append(resp.Addresses, addr)
		}
	}

	return resp
}

func (this *ProbeNetbios) CreateStatusRequest() []byte {
	return []byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)),
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
	}
}

func (this *ProbeNetbios) CreateNameRequest(name string) []byte {
	nbytes := [16]byte{}
	copy(nbytes[0:15], []byte(strings.ToUpper(name)[:]))

	req := []byte{
		byte(rand.Intn(256)), byte(rand.Intn(256)),
		0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x20,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00, 0x00, 0x20, 0x00, 0x01,
	}

	encoded := this.EncodeNetbiosName(nbytes)
	copy(req[13:45], encoded[0:32])
	return req
}

func (this *ProbeNetbios) GetnamebyIP(inip string) string {
	// Open socket
	buff := make([]byte, 1500)
	this.socket, _ = net.ListenPacket("udp", "")	
	this.SendStatusRequest(inip)
	for {
		this.socket.SetReadDeadline(time.Now().Add(time.Duration( 2 )*time.Second))
		rlen, raddr, rerr := this.socket.ReadFrom(buff)
		if rerr != nil {
			if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
				//logs.Info("probe %s receiver timed out: %s", this, rerr)
				break
			}
			// Complain about other error types
			log.Printf("probe %s receiver returned error: %s", this, rerr)
			return ""
		}

		ip := raddr.(*net.UDPAddr).IP.String()
		if ip != inip{
			continue
		}
		reply := this.ParseReply(buff[0 : rlen-1])

		if reply.Header.RecordType != 0x21 {
			continue
		}
		
		if len(reply.Names) == 0 && len(reply.Addresses) == 0 {
			continue
		}
		if len(reply.HostName) > 0{
			return TrimName(string(reply.HostName[:]))
		}
	}
	return ""
}
