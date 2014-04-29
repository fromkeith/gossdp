/*
 * Copyright (c) 2013, fromkeith
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * * Neither the name of the fromkeith nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package gossdp

import (
    "strings"
    "regexp"
    "log"
    "time"
    "net"
    "os"
    "fmt"
    "runtime"
    "code.google.com/p/go.net/ipv4"
)

var (
    httpHeader = regexp.MustCompile(`HTTP\/\d{1}\.\d{1} \d+ .*`)
    ssdpHeader = regexp.MustCompile(`^([^:]+):\s*(.*)$`)
)

type ssdp struct {
    responses       map[string]bool
    usns            map[string]string
    httphost        string
    description     string
    ttl             string
    ssdpSig         string
    udp             string
    ipport          string
    ssdpPort        string
    ssdpIp          string
    ssdpTtl         string
    rawSocket       net.PacketConn
    socket          *ipv4.PacketConn
    udn             string
    listener        SsdpListener
}

type RequestInfo struct {
    Address         string
    Port            string
}

type SsdpListener interface {
    AdvertiseAlive(headers map[string]string)
    AdvertiseBye(headers map[string]string)
    Response(msg string, rinfo RequestInfo)
}

func NewSsdp(l SsdpListener, signature, ssdpIp, ssdpPort, ssdpTtl, ttl, description, udn string) (*ssdp, error) {
    var s ssdp
    s.listener = l
    s.ssdpSig = signature
    s.ssdpIp = ssdpIp
    s.ssdpPort = ssdpPort
    s.ssdpTtl = ssdpTtl
    s.ipport = s.ssdpIp + ":" + s.ssdpPort
    s.ttl = ttl
    s.description = description
    s.usns = make(map[string]string)
    s.udn = udn
    if err := s.createSocket(); err != nil {
        return nil, err
    }

    return &s, nil
}

func (s *ssdp) parseMessage(message string, rinfo RequestInfo) {
    msgType := strings.Split(message, "\r\n")

    if httpHeader.MatchString(msgType[0]) {
        s.parseResponse(message, rinfo)
    } else {
        s.parseCommand(message, rinfo)
    }
}

func (s *ssdp) parseCommand(msg string, rinfo RequestInfo) {
    msgContent := strings.Split(msg, "\r\n")
    msgType := strings.Split(msgContent[0], " ")
    method := msgType[0]

    headers := make(map[string]string)

    for _, line := range msgContent {
        if len(line) > 0 {
            matches := ssdpHeader.FindAllStringSubmatch(line, -1)
            if len(matches) == 1 && len(matches[0]) == 3 {
                headers[strings.ToUpper(matches[0][1])] = matches[0][2]
            }
        }
    }

    if method == "NOTIFY" {
        s.notify(headers, msg, rinfo)
        return
    }
    log.Println("Method ", method)
    if method == "M-SEARCH" {
        s.msearch(headers, msg, rinfo)
        return
    }
    log.Println("Unknown message type!. Message: " + msg + ". type:" + method)
}


func (s *ssdp) notify(headers map[string]string, msg string, rinfo RequestInfo) {
    var nts string
    var ok bool
    if nts, ok = headers["NTS"]; !ok {
        log.Println("Message missing NTS!: " + msg)
        return
    }
    nts = strings.ToLower(nts)
    if nts == "ssdp:alive" {
        s.listener.AdvertiseAlive(headers)
        return
    }
    if nts == "ssdp:byebye" {
        s.listener.AdvertiseBye(headers)
        return
    }
    log.Println("could not identify NTS header!: " + msg)
}


func (s *ssdp) msearch(headers map[string]string, msg string, rinfo RequestInfo) {
    if _, ok := headers["MAN"]; !ok {
        return
    }
    if _, ok := headers["MX"]; !ok {
        return
    }
    if st, ok := headers["ST"]; !ok {
        return
    } else {
        s.inMSearch(st, rinfo)
    }
}


func (s *ssdp) parseResponse(msg string, rinfo RequestInfo) {
    if _, ok := s.responses[rinfo.Address]; !ok {
        s.responses[rinfo.Address] = true
    }
    s.listener.Response(msg, rinfo)
}


func (s *ssdp) inMSearch(st string, rinfo RequestInfo) {
    if st[0] == '"' && st[len(st) - 1] == '"' {
        st = st[1:len(st) - 2]
    }

    peer := rinfo.Address
    port := rinfo.Port

    for k, v := range s.usns {
        if st == "ssdp:all" || k == st {
            pkt := s.getSSDPHeader(
                "200 OK",
                map[string]string{
                    "ST": k,
                    "USN": v,
                    "LOCATION": s.httphost + "/" + s.description,
                    "CACHE-CONTROL": "max-age" + s.ttl,
                    "DATE": time.Now().Format(time.RFC3339), // TODO: proper format
                    "SERVER": s.ssdpSig,
                    "EXT": "",
                },
                true,
            )
            msg := newBuffer(pkt)
            addr, _ := net.ResolveUDPAddr("udp4", net.JoinHostPort(peer, port))
            _, err := s.rawSocket.WriteTo(msg, addr)
            log.Println("WriteTo: ", err)
        }
    }
}

func newBuffer(pkt string) []byte {
    return []byte(pkt)
}


func (s  *ssdp) AddUsn(device string) {
    s.usns[device] = s.udn + "::" + device
}

func (s *ssdp) Search(st string) error {
    hostname, err := os.Hostname()
    if err != nil {
        return err
    }
    _, err = net.LookupHost(hostname)
    if err != nil {
        return err
    }
    pkt := s.getSSDPHeader(
        "M-SEARCH",
        map[string]string{
            "HOST": s.ipport,
            "ST": st,
            "MAN": `"ssdp:discover"`,
            "MX": "3",
        },
        false,
    )
    msg := newBuffer(pkt)
    addr, _ := net.ResolveUDPAddr("udp", s.ssdpIp + ":" + s.ssdpPort)
    s.socket.WriteTo(msg, nil, addr)
    return nil
}

func (s *ssdp) Server(ip, portno string) {
    s.usns[s.udn] = s.udn

    s.advertise(false)
    advertiseTimer(s, 1 * time.Second)
    advertiseTimer(s, 2 * time.Second)
    advertiseTimer(s, 3 * time.Second)
    advertiseTimer(s, 10 * time.Second)
}
func advertiseTimer(s * ssdp, d time.Duration) {
    time.AfterFunc(10 * time.Second, func () {
        if s.socket != nil {
            s.advertise(false)
        }
    })
}


func (s *ssdp) Stop() {
    if s.socket != nil {
        s.advertise(false)
        s.advertise(false)
        s.socket.Close()
        s.socket = nil
        s.rawSocket.Close()
        s.rawSocket = nil
    }
}

func (s * ssdp) advertise(alive bool) {
    if s.socket == nil {
        return
    }
    ntsString := "ssdp:alive"
    if !alive {
        ntsString = "ssdp:byebye"
    }
    for k, v := range s.usns {
        heads := map[string]string{
            "HOST": s.ipport,
            "NT": k,
            "NTS": ntsString,
            "USN": v,
        }
        if alive {
            heads["LOCATION"] = s.httphost + "/" + s.description
            heads["CACHE-CONTROL"] = "max-age=1800"
            heads["SERVER"] = s.ssdpSig
        }
        msg := newBuffer(
            s.getSSDPHeader(
                "NOTIFY",
                heads,
                false,
            ),
        )
        to, err := net.ResolveUDPAddr("udp", s.ssdpIp + ":" + s.ssdpPort)
        if err == nil {
            s.socket.WriteTo(msg, nil, to)
        }
    }
}

func (s * ssdp) getSSDPHeader(head string, vars map[string]string, res bool) string {
    var ret string
    if res {
        ret = fmt.Sprintf("HTTP/1.1 %s\r\n", head)
    } else {
        ret = fmt.Sprintf("%s * HTTP/1.1\r\n", head)
    }
    for k, v := range vars {
        ret += fmt.Sprintf("%s: %s\r\n", k, v)
    }
    return ret + "\r\n"
}


func GetSsdpSignature() string {
    return fmt.Sprintf("go/%s UPnP/1.1 gossdp/0.1", runtime.Version())
}

func (s * ssdp) createSocket() error {

    group := net.IPv4(239, 255, 255, 250)
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Println("net.Interffaces")
        return err
    }
    con, err := net.ListenPacket("udp4", "0.0.0.0:1900")
    if err != nil {
        log.Println("listenPAcket")
        return err
    }
    p := ipv4.NewPacketConn(con)
    p.SetMulticastLoopback(true)
    for i, v := range interfaces {
        err = p.JoinGroup(&v, &net.UDPAddr{IP: group})
        if err != nil {
            log.Println("join group ", i, " ", err)
            continue
        }
    }
    s.socket = p
    s.rawSocket = con
    return nil
}

func (s * ssdp) Listen() {
    readBytes := make([]byte, 2048)
    for {
        n, src, err := s.rawSocket.ReadFrom(readBytes)
        if err != nil {
            log.Println("Same old error: ", err)
            return
        }
        log.Println("SRC", src)
        if n > 0 {
            host, port, _ := net.SplitHostPort(src.String())
            s.parseMessage(string(readBytes[0:n]), RequestInfo{
                host,
                port,
            })
        }
    }
}