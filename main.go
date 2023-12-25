package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	handle        *pcap.Handle
	err           error
	dstConnection net.Conn
)

func main() {
	//检查参数
	if strings.TrimSpace(pcapFilePath) == "" {
		fmt.Println("没有指定需要回放的Pcap文件路径")
		flag.Usage()
		os.Exit(1)
	}
	if strings.TrimSpace(protocol) == "" {
		fmt.Println("没有指定目标协议")
		flag.Usage()
		os.Exit(1)
	} else if protocol != "tcp" && protocol != "udp" {
		fmt.Println("不支持的目标协议:", protocol)
		flag.Usage()
		os.Exit(1)
	}

	if strings.TrimSpace(destination) == "" {
		fmt.Println("没有指定目标IP和端口")
		flag.Usage()
		os.Exit(1)
	} else {
		reg := regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}:(\\d+)")
		if reg.MatchString(destination) == false {
			fmt.Println("指定目标IP和端口格式错误:", destination)
			flag.Usage()
			os.Exit(1)
		}
	}
	if n, e := net.Dial(protocol, destination); e != nil {
		fmt.Println("连接目标端口失败,目标=", destination, ",协议=", protocol)
		os.Exit(1)
	} else {
		dstConnection = n
	}
	defer dstConnection.Close()
	st := time.Now()
	var cnt int
	defer func() {
		fmt.Printf("共发送%d包,耗时%v\n", cnt, time.Now().Sub(st))
	}()
	if replayCount == 0 {
		for {
			handle, err = pcap.OpenOffline(pcapFilePath)
			if err != nil {
				log.Fatal(err)
			}
			// Set filter
			err = handle.SetBPFFilter(bfpFilter)
			if err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				dealPacket(packet)
				cnt++
			}
			handle.Close()
		}
	} else {
		for i := 0; i < replayCount; i++ {
			handle, err = pcap.OpenOffline(pcapFilePath)
			if err != nil {
				log.Fatal(err)
			}

			// Set filter
			err = handle.SetBPFFilter(bfpFilter)
			if err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				dealPacket(packet)
				cnt++
			}
			handle.Close()
		}
	}
}

func dealPacket(packet gopacket.Packet) {
	time.Sleep(time.Duration(interval) * time.Microsecond) //停顿,避免发包过快
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if ethernetPacket.EthernetType.String() == "IPv4" {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					handleUdpPackage(udp)
				}
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := udpLayer.(*layers.TCP)
					handleTcpPackage(tcp)
				}
			}
		}
	}
}

func handleTcpPackage(pkg *layers.TCP) {
	//fmt.Printf("%X\n", pkg.Payload)
	if _, e := dstConnection.Write(pkg.Payload); e != nil {
		fmt.Println("发送TCP包失败:", e)
	}
}

func handleUdpPackage(pkg *layers.UDP) {
	//fmt.Printf("%X\n", pkg.Payload)
	if _, e := dstConnection.Write(pkg.Payload); e != nil {
		fmt.Println("发送UDP包失败:", e)
	}
}
