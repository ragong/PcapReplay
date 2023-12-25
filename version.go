package main

import (
	"flag"
	"os"
)

var (
	pcapFilePath string
	bfpFilter    string
	destination  string
	protocol     string
	replayCount  int
	interval     int
)

func init() {
	var showHelp bool
	flag.BoolVar(&showHelp, "h", false, "show build version")
	flag.StringVar(&pcapFilePath, "f", "", "需要回放的Pcap文件路径")
	flag.StringVar(&bfpFilter, "bpf", "", "BPF过滤条件")
	flag.StringVar(&protocol, "p", "", "目标协议:tcp/udp")
	flag.StringVar(&destination, "d", "", "目标IP和端口,例如127.0.0.1:9000")
	flag.IntVar(&replayCount, "r", 1, "回放次数,设置为0,无限回放")
	flag.IntVar(&interval, "i", 100, "发包间隔(微秒),用于流控")
	flag.Parse()
	if showHelp {
		flag.Usage()
		os.Exit(0)
	}
}
