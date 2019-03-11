<h1 align="center">StreamDump</h1>

[README](README.md) | [中文文档](README_zh.md)

### StreamDump
StreamDump 用于将 pcap 或网卡中的流量根据四元组进行切割，每个数据流单独存入一个 pcap 文件，超过两分钟没有数据交换的连接视为连接断开

## 特性

- 支持 BPF 过滤规则，可根据需求进行自定义
- 支持捕获双向数据流，保存名称为四元组`IP[Port]-IP[Port].pcap`，以捕获到的第一个 packet 中的四元组参数进行命名
- 支持从 pcap 或网卡中捕获流量
- 用 Golang 编写，安装部署方便,支持交叉编译


## 编译
`go build -o streamdump streamdump.go`

## 使用流程

1. 编译，或者下载[已经编译好的可执行文件](https://github.com/scu-igroup/StramDump/releases)
2. 设置过滤规则，流量来源（pcap 文件或者网卡）
3. 运行程序

## 用例
```bash
Usage: streamdump [-hv] [-i interface]
Options:
  -b    Capture bidirectional data flow
  -d string
        The domain name of the packet to be captured
  -f string
        BPF filter rules for pcap (default "tcp")
  -h    print this help message and exit
  -i string
        Interface to get packets from (default "en0")
  -l int
        SnapLen for pcap packet capture (default 1600)
  -promisc
        Set promiscuous mode (default true)
  -r string
        Filename to read from, overrides -i
  -s string
        Filepath to save pcap files (default "./pcap_s")
  -v    Logs every packet in great detail
```

```bash
#从默认网卡（en0）捕获 Google.com 对应 ip 以及 80 端口的 tcp 流量: 
>./streamdump -f 'tcp and port 80' -s '/home/stream/' -d 'google.com'
#从 pcap 文件中过滤 Google.com 对应 ip 以及 443 端口的 tcp 流量：
>./streamdump -f 'tcp and port 443' -s '/home/stream/' -d 'google.com'
#从自定义网卡（如：eth0）捕获 Google.com 对应 ip 以及 443 端口的 tcp 流量：
>./streamdump -i eth0 -f 'tcp and port 443' -s '/home/stream/' -d 'google.com'
#从自定义网卡捕获特定 ip 以及 443 端口的 tcp 流量，将双向数据都保存在一个 pcap 文件中：
>./streamdump -i eth0 -f 'host 39.96.128.184 and port 443' -s '/home/stream/ -b'
#...
>...
```
