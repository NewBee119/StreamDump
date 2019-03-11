<h1 align="center">StreamDump</h1>

[README](README.md) | [中文文档](README_zh.md)

### What is StreamDump？
StreamDump is used to cut traffic packets from a pcap format file or network interface by quaternions(src_ip,src_port,dst_ip,dst_port), each TCP stream is stored in a separate pcap file, and any connection without data exchange for more than two minutes is considered disconnected.

## Features

- BPF filtering rules are supported and can be customized according to requirements.
- Support to capture the bidirectional data flow, the file's name to be saved is formatted with` IP[Port]-IP[Port].pcap`, the arguments used for the file's name of the bidirectional data flow comes from the first captured package.
- Support capturing traffic from pcap format file or a network interface.
- Written in Golang, easy installation, and deployment, support cross compilation.


## How to Build
`go build -o streamdump streamdump.go`

## Usage
1. Compile, or download the compiled executable [file](https://github.com/scu-igroup/StramDump/releases).
2. Set filter rules and traffic sources (pcap format file or network interface)
3. run

## Example
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
#Capture the TCP traffic for the IP address of 'google.com' and port 80 from the default network interface (en0): 
>./streamdump -f 'tcp and port 80' -s '/home/stream/' -d 'google.com'

#Filter the TCP traffic for IP of 'google.com' IP and port 443 from the pcap file：
>./streamdump -f 'tcp and port 443' -s '/home/stream/' -d 'google.com'

#Capture the TCP traffic for IP of 'google.com' and port 443 from a custom network interface such as eth0：
>./streamdump -i eth0 -f 'tcp and port 443' -s '/home/stream/' -d 'google.com'

#Capture the TCP traffic for a specific IP and port 443 from the custom network interface and store the bidirectional data to a pcap file：
>./streamdump -i eth0 -f 'host 39.96.128.184 and port 443' -s '/home/stream/ -b'
#...
>...
```
