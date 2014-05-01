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

/*


USN:
    uuid:device-UUID::upnp:rootdevice
        Snet once per root device
    uuid:device-UUID
        Sent once per device. Device-UUID unique for all devices.
    uuid:device-UUID::urn:domain-name:device:deviceType:v
        Sent once per device. device-UUID, domain-name, device, deviceType and v (version)
        defined by vendor. Periods in domainname should be replaced with '-'



*/
package gossdp

import (
    "strings"
    "regexp"
    "log"
    "time"
    "net"
    "fmt"
    "code.google.com/p/go.net/ipv4"
    "bytes"
    "errors"
    "strconv"
    "net/http"
    "bufio"
)

var (
    cacheControlAge = regexp.MustCompile(`.*max-age=([0-9]+).*`)
)

type ssdp struct {
    advertisableServers     map[string][]AdvertisableServer
    deviceIdToServer        map[string]AdvertisableServer
    rawSocket       net.PacketConn
    socket          *ipv4.PacketConn
    listener        SsdpListener
    listenSearchTargets         map[string]bool
}


// The common SSDP fields in the Notify ssdp:alive message.
// Raw headers are in RawHeaders, and names are all uppercase.\
//
// Notify (alive)
//      NOTIFY * HTTP/1.1
//      Host: 239.255.255.250:1900
//      NT: blenderassociation:blender               // notification type. Aka search target.
//      NTS: ssdp:alive                              // message sub-type. Either ssdp:alive or ssdp:byebye
//      USN: someunique:idscheme3                    // Unique Service Name. An instance of a device
//      LOCATION: <blender:ixl><http://foo/bar>      // location of the service being advertised. Eg. http://hello.com
//      Cache-Control: max-age = 7393                // how long this is valid for. as defined by http standards
//      SERVER: WIN/8.1 UPnP/1.0 gossdp/0.1                  // Concat of OS, UPnP, and product.
type AliveMessage struct {
    SearchType      string
    DeviceId        string
    Usn             string
    Location        string
    MaxAge          int
    Server          string
    RawRequest      *http.Request
}

// Notify (bye): server-only:
//      NOTIFY * HTTP/1.1
//      Host: 239.255.255.250:1900
//      NT: search:target
//      NTS: ssdp:byebye
//      USN: uuid:the:unique
type ByeMessage struct {
    SearchType      string
    Usn             string
    DeviceId        string
    RawRequest      *http.Request
}

// search-response: server-only:
//      HTTP/1.1 200 OK
//      Ext:                                                 // required by http extension framework. just key, no value
//      Cache-Control: max-age = 5000                        // number of seconds this message is valid for
//      ST: ge:fridge                                        // Search target. respond with all matching targets. Same as NT in Notify messages
//      USN: uuid:abcdefgh-7dec-11d0-a765-00a0c91e6bf6       // Unique Service name
//      LOCATION: <blender:ixl><http://foo/bar>              // location of the service being advertised. Eg. http://hello.com
//      SERVER: WIN/8.1 UPnP/1.0 gossdp/0.1                  // Concat of OS, UPnP, and product.
//      DATE: date of response                               // rfc1123-date of the response
type ResponseMessage struct {
    MaxAge              int
    SearchType          string
    Usn                 string
    DeviceId            string
    Location            string
    Server              string
    RawResponse         *http.Response
}

type SsdpListener interface {
    NotifyAlive(message AliveMessage)
    NotifyBye(message ByeMessage)
    Response(message ResponseMessage)
}

// reference doc: http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20081015.pdf


// search: client-only:
// M-SEARCH * HTTP/1.1
// Host: 239.255.255.250:1900
// Man: "ssdp:discover"                                 // message sub-type
// ST: ge:fridge                                        // search target
                                                        //  ssdp:all -> all targets
                                                        //  uuid:device-UUID    -> particular target
                                                        //  urn:domainname:service:servicetype:v
// MX: 3                                                // maximum wait time in seconds.
                                                        //  Response time should be random between 0 and this number




type AdvertisableServer struct {
    // The type of this service. In the URN it is pasted after the device-UUID.
    //  It is what devices will search for
    ServiceType             string
    // The unique identifier of this device.
    DeviceUuid              string
    // The location of the service we are advertising. Eg. http://192.168.0.2:3434
    Location                string
    // The max number of seconds we want advertise and responses to be valid for.
    MaxAge                  int

    usn                     string
}

const (
    serverName = "windows/8.1 UPnP/1.0 gossdp/0.1"
)

// Register a service to advertise
func (s * ssdp) AdvertiseServer(ads AdvertisableServer) {
    ads.usn = fmt.Sprintf("uuid:%s::%s", ads.DeviceUuid, ads.ServiceType)
    if v, ok := s.advertisableServers[ads.ServiceType]; ok {
        s.advertisableServers[ads.ServiceType] = append(v, ads)
    } else {
        s.advertisableServers[ads.ServiceType] = []AdvertisableServer{ads}
    }
    s.deviceIdToServer[ads.DeviceUuid] = ads
    s.advertiseTimer(ads, 0 * time.Second)
    s.advertiseTimer(ads, 1 * time.Second)
    s.advertiseTimer(ads, 3 * time.Second)
    s.advertiseTimer(ads, 10 * time.Second)
}



func NewSsdp(l SsdpListener) (*ssdp, error) {
    var s ssdp
    s.advertisableServers = make(map[string][]AdvertisableServer)
    s.deviceIdToServer = make(map[string]AdvertisableServer)
    s.listenSearchTargets = make(map[string]bool)
    s.listener = l
    if err := s.createSocket(); err != nil {
        return nil, err
    }

    return &s, nil
}

func (s *ssdp) parseMessage(message, hostPort string) {
    req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(message)))
    if err != nil {
        s.parseResponse(message, hostPort)
        return
    }

    if req.URL.Path != "*" {
        log.Println("Unknown path requested: ", req.URL.Path)
        return
    }

    s.parseCommand(req, hostPort)
}

func (s *ssdp) parseCommand(req * http.Request, hostPort string) {
    if req.Method == "NOTIFY" {
        s.notify(req)
        return
    }
    if req.Method == "M-SEARCH" {
        s.msearch(req, hostPort)
        return
    }
    log.Println("Unknown message type!. Message: " + req.Method)
}


func (s *ssdp) notify(req * http.Request) {
    if s.listener == nil {
        return
    }
    nts := req.Header.Get("NTS")
    if nts == "" {
        log.Println("Missing NTS in NOTIFY")
        return
    }
    searchType := req.Header.Get("NT")
    if searchType == "" {
        log.Println("Missing NT in NOTIFY")
        return
    }
    usn := req.Header.Get("USN")

    var deviceId string
    if len(usn) > 0 {
        parts := strings.Split(usn, ":")
        if len(parts) > 2 {
            if parts[0] == "uuid" {
                deviceId = parts[1]
            }
        }
    }

    nts = strings.ToLower(nts)
    if nts == "ssdp:alive" {
        location := req.Header.Get("LOCATION")
        server := req.Header.Get("SERVER")
        maxAge := -1
        if cc := req.Header.Get("CACHE-CONTROL"); cc != "" {
            subMatch := cacheControlAge.FindStringSubmatch(cc)
            if len(subMatch) == 2 {
                maxAgeInt64, err := strconv.ParseInt(subMatch[1], 10, 0)
                if err != nil {
                    maxAge = int(maxAgeInt64)
                }
            }
        }
        message := AliveMessage {
            SearchType      : searchType,
            DeviceId        : deviceId,
            Usn             : usn,
            Location        : location,
            MaxAge          : maxAge,
            Server          : server,
            RawRequest      : req,
        }
        s.listener.NotifyAlive(message)
        return
    }
    if nts == "ssdp:byebye" {
        message := ByeMessage{
            SearchType      : searchType,
            Usn             : usn,
            DeviceId        : deviceId,
            RawRequest      : req,
        }
        s.listener.NotifyBye(message)
        return
    }
    log.Println("Could not identify NTS header!: " + nts)
}


func (s *ssdp) msearch(req * http.Request, hostPort string) {
    if v := req.Header.Get("MAN"); v == "" {
        return
    }
    if v := req.Header.Get("MX"); v == "" {
        return
    }
    if st := req.Header.Get("ST"); st == "" {
        return
    } else {
        s.inMSearch(st, req, hostPort) // TODO: extract MX
    }
}


func (s *ssdp) parseResponse(msg, hostPort string) {
    if s.listener == nil {
        return
    }
    resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(msg)), nil)
    if err != nil {
        log.Println("Not a valid response! ", err)
        return
    }
    defer resp.Body.Close()

    maxAge := -1
    if cc := resp.Header.Get("CACHE-CONTROL"); cc != "" {
        subMatch := cacheControlAge.FindStringSubmatch(cc)
        if len(subMatch) == 2 {
            maxAgeInt64, err := strconv.ParseInt(subMatch[1], 10, 0)
            if err != nil {
                maxAge = int(maxAgeInt64)
            }
        }
    }
    var deviceId string
    usn := resp.Header.Get("USN")
    if len(usn) > 0 {
        parts := strings.Split(usn, ":")
        if len(parts) > 2 {
            if parts[0] == "uuid" {
                deviceId = parts[1]
            }
        }
    }

    respMessage :=ResponseMessage{
        MaxAge              : maxAge,
        SearchType          : resp.Header.Get("ST"),
        Usn                 : usn,
        DeviceId            : deviceId,
        Location            : resp.Header.Get("LOCATION"),
        Server              : resp.Header.Get("SERVER"),
        RawResponse         : resp,
    }

    s.listener.Response(respMessage)
}


func (s *ssdp) inMSearch(st string, req * http.Request, sendTo string) {
    if st[0] == '"' && st[len(st) - 1] == '"' {
        st = st[1:len(st) - 2]
    }
    mx := 0
    if mxStr := req.Header.Get("MX"); mxStr != "" {
        mxInt64, err := strconv.ParseInt(mxStr, 10, 0)
        if err != nil {
            mx = int(mxInt64)
        }
    }

    // todo: use another routine for the timeout
    // todo: make it random
    time.Sleep(time.Duration(mx) * time.Second)

    if st == "ssdp:all" {
        for _, v := range s.advertisableServers {
            for _, d := range v {
                s.respondToMSearch(d, sendTo)
            }
        }
    } else if d, ok := s.deviceIdToServer[st]; ok {
        s.respondToMSearch(d, sendTo)
    } else if v, ok := s.advertisableServers[st]; ok {
        for _, d := range v {
            s.respondToMSearch(d, sendTo)
        }
    }
}

func (s * ssdp) respondToMSearch(ads AdvertisableServer, sendTo string) {
    msg := s.createSsdpHeader(
        "200 OK",
        map[string]string{
            "ST": ads.ServiceType,
            "USN": ads.usn,
            "LOCATION": ads.Location,
            "CACHE-CONTROL": fmt.Sprintf("max-age=%d", ads.MaxAge),
            "DATE": time.Now().Format(time.RFC1123),
            "SERVER": serverName,
            "EXT": "",
        },
        true,
    )
    addr, err := net.ResolveUDPAddr("udp4", sendTo)
    if err != nil {
        log.Println("Error resolving UDP addr: ", err)
        return
    }
    _, err = s.rawSocket.WriteTo(msg, addr)
    if err != nil {
        log.Println("WriteTo: ", err)
    }
}

func (s *ssdp) ListenFor(searchTarget string) error {

    // listen directly for their search target
    s.listenSearchTargets[searchTarget] = true

    msg := s.createSsdpHeader(
        "M-SEARCH",
        map[string]string{
            "HOST": "239.255.255.250:1900",
            "ST": searchTarget,
            "MAN": `"ssdp:discover"`,
            "MX": "3",
        },
        false,
    )
    addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
    if err != nil {
        return err
    }
    _, err = s.rawSocket.WriteTo(msg, addr)
    return err
}


func (s * ssdp) advertiseTimer(ads AdvertisableServer, d time.Duration) {
    time.AfterFunc(d, func () {
        s.advertiseServer(ads, true)
    })
}


func (s *ssdp) Stop() {
    if s.socket != nil {
        // TODO: advertise bye for everyone.s
        //s.advertise(false)
        //s.advertise(false)
        s.socket.Close()
        s.socket = nil
        s.rawSocket.Close()
        s.rawSocket = nil
    }
}

func (s * ssdp) advertiseServer(ads AdvertisableServer, alive bool) {
    if s.socket == nil {
        return
    }
    ntsString := "ssdp:alive"
    if !alive {
        ntsString = "ssdp:byebye"
    }

    heads := map[string]string{
        "HOST": "239.255.255.250:1900",
        "NT": ads.ServiceType,
        "NTS": ntsString,
        "USN": ads.usn,
    }
    if alive {
        heads["LOCATION"] = ads.Location
        heads["CACHE-CONTROL"] = fmt.Sprintf("max-age=%d", ads.MaxAge)
        heads["SERVER"] = serverName
    }
    msg := s.createSsdpHeader(
            "NOTIFY",
            heads,
            false,
        )
    to, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
    if err == nil {
        if _, err := s.rawSocket.WriteTo(msg, to); err != nil {
            log.Println("Failed to advertise: ", err)
        } else {
            log.Println("Advertise!")
        }
    } else {
        log.Println("Error sending advertisement: ", err)
    }
}

func (s * ssdp) createSsdpHeader(head string, vars map[string]string, res bool) []byte {
    buf := bytes.Buffer{}
    if res {
        buf.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", head))
    } else {
        buf.WriteString(fmt.Sprintf("%s * HTTP/1.1\r\n", head))
    }
    for k, v := range vars {
        buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
    }
    buf.WriteString("\r\n")
    return []byte(buf.String())
}

func (s * ssdp) createSocket() error {

    group := net.IPv4(239, 255, 255, 250)
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Println("net.Interfaces error", err)
        return err
    }
    con, err := net.ListenPacket("udp4", "0.0.0.0:1900")
    if err != nil {
        log.Println("net.ListenPacket error: ", err)
        return err
    }
    p := ipv4.NewPacketConn(con)
    p.SetMulticastLoopback(true)
    didFindInterface := false
    for i, v := range interfaces {
        err = p.JoinGroup(&v, &net.UDPAddr{IP: group})
        if err != nil {
            log.Println("join group ", i, " ", err)
            continue
        }
        didFindInterface = true
    }
    if !didFindInterface {
        return errors.New("Unable to find a compatible network interface!")
    }
    s.socket = p
    s.rawSocket = con
    return nil
}

func (s * ssdp) Start() {
    readBytes := make([]byte, 2048)
    for {
        n, src, err := s.rawSocket.ReadFrom(readBytes)
        if err != nil {
            log.Println("Error reading from socket: ", err)
            return
        }
        if n > 0 {
            log.Println("Message: ", string(readBytes[0:n]))
            s.parseMessage(string(readBytes[0:n]), src.String())
        }
    }
}