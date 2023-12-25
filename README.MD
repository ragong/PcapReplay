# Pcap抓包回放工具


## 功能
1,用于回放抓取的Pcap包;  
2,支持Udp和Tcp协议;  
3,支持自定义发包间隔和重复发包(用于流控和压测);  

## 参数说明
```text
  -bpf string                          
        BPF过滤条件                    
  -d string                            
        目标IP和端口,例如127.0.0.1:9000
  -f string                            
        需要回放的Pcap文件路径         
  -h    show build version             
  -i int                               
        发包间隔(纳秒) (default 10)    
  -p string                            
        目标协议:tcp/udp               
  -r int                               
        回放次数,设置为0,无限回放 (default 1)
```

example
```text
PcapReplay.exe -d 127.0.0.1:9100 -f ./test.pcap -p udp

//回放./test.pcap里面的包,并用udp协议发送到127.0.0.1:9100端口
```
