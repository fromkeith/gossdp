package main

import (
    "github.com/fromkeith/gossdp"
    "log"
    "time"
)

type blah struct {

}

func (b blah) AdvertiseAlive(headers map[string]string) {
    log.Println("AdvertiseAlive")
}
func (b blah) AdvertiseBye(headers map[string]string) {
    log.Println("AdvertiseBye")
}
func (b blah) Response(msg string, rinfo gossdp.RequestInfo) {
    log.Println("Response")
}

func main() {

    s, err := gossdp.NewSsdp(blah{}, gossdp.GetSsdpSignature(),
        "239.255.255.250",
        "1900",
        "1",
        "1800",
        "upnp/desc.html",
        "uuid:f40c2981-7329-40b7-8b04-27f187aecfb5")
    if err != nil {
        log.Println("Error reating ssdp: ", err)
        return
    }
    s.AddUsn("urn:yewwshare:1")
    s.Server("", "")
    time.AfterFunc(30 * time.Second, func () {
        s.Stop()
    })
    s.Listen()
}