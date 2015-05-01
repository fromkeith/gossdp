package main

import (
    "github.com/fromkeith/gossdp"
    "log"
    "time"
    //"os"
)

type blah struct {

}

func (b blah) NotifyAlive(message gossdp.AliveMessage) {
    log.Printf("NotifyAlive %#v\n", message)
}
func (b blah) NotifyBye(message gossdp.ByeMessage) {
    log.Printf("NotifyBye %#v\n", message)
}
func (b blah) Response(message gossdp.ResponseMessage) {
    log.Printf("Response %#v\n", message)
}

func testServer() {
    s, err := gossdp.NewSsdp(nil)
    if err != nil {
        log.Println("Error creating ssdp server: ", err)
        return
    }
    defer s.Stop()
    go s.Start()

    serverDef := gossdp.AdvertisableServer{
        ServiceType: "urn:fromkeith:test:web:1",
        DeviceUuid: "hh0c2981-0029-44b7-4u04-27f187aecf78",
        Location: "http://192.168.1.1:8080",
        MaxAge: 3600,
    }
    s.AdvertiseServer(serverDef)
    time.Sleep(30 * time.Second)
}

func testClient() {
    b := blah{}
    c, err := gossdp.NewSsdpClient(b)
    if err != nil {
        log.Println("Failed to start client: ", err)
        return
    }
    defer c.Stop()
    go c.Start()

    err = c.ListenFor("urn:fromkeith:test:web:1")
    time.Sleep(30 * time.Second)
}

func main() {
    testServer()
    //go testServer()
    //time.Sleep(5 * time.Second)
    //testClient()
}