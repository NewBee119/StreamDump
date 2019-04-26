// Copyright scu-igroup. All rights reserved.
//
// Use of this source code is governed by a MIT-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary use the gopacket TCP assembler to assemble the tcp
// stream from the interface or a file of Pcap format.
package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"net"
	"os"
	"path"
	"time"
)

var version = "0.0.2"

type assemblerFactory struct {
}

func (af *assemblerFactory) New() *streamPool {
	return &streamPool{poolmap: make(map[string]*tcpStream)}
}

type streamPool struct {
	poolmap map[string]*tcpStream
}

type tcpStream struct {
	f        *os.File
	w        *pcapgo.Writer
	lastseen time.Time
}

func (sp *streamPool) FlushOlderThan(t time.Time) (flushed int) {
	for k, ts := range sp.poolmap {
		if ts.lastseen.Before(t) {
			if err := ts.f.Close(); err != nil {
				log.Fatal(err)
			}
			delete(sp.poolmap, k)
			flushed++
		}
	}
	return
}

func PathExists(path *string) (bool, error) {
	_, err := os.Stat(*path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		// 创建文件夹
		err := os.MkdirAll(*path, os.ModePerm)
		if err != nil {
			log.Printf("mkdir failed![%v]\n", err)
		} else {
			log.Printf("mkdir success!\n")
			return true, nil
		}

	}

	return false, err
}

var (
	iface         = flag.String("i", "", "Interface to get packets from")
	fpath         = flag.String("s", "./pcap_s", "Filepath to save pcap files")
	fname         = flag.String("r", "", "Filename to read from, overrides -i")
	snaplen       = flag.Int("l", 1600, "SnapLen for pcap packet capture")
	filter        = flag.String("f", "tcp", "BPF filter rules for pcap")
	bidirection   = flag.Bool("b", false, "Capture bidirectional data flow")
	help          = flag.Bool("h", false, "print this help message and exit")
	domain        = flag.String("d", "", "The domain name of the packet to be captured")
	logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
	promisc       = flag.Bool("promisc", true, "Set promiscuous mode")
)

func usage() {
	if _, err := fmt.Fprintf(os.Stderr, "StreamDump Version: StreamDump-%v\nUsage: streamdump [-hv] [-i interface]\nOptions:\n", version); err != nil {
		log.Fatal(err)
	}
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
}

func main() {

	var handle *pcap.Handle
	var err error
	var ip []string

	flag.Parse()
	if *help {
		flag.Usage()
		return
	}
	if *domain != "" {
		ip, _ = net.LookupHost(*domain)
	}
	// Set up pcap packet capture
	if *iface != "" {
		log.Printf("Starting capture on interface %q", *iface)
		if handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever); err != nil {
			log.Fatal(err)
		}
	} else if *fname != "" {
		log.Printf("Starting parsing pcap file from %q", *fname)
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("Pcap OpenOffline error:", err)
		}
	} else {
		log.Printf("Starting capture on interface %q", "eth0")
		if handle, err = pcap.OpenLive("eth0", int32(*snaplen), *promisc, pcap.BlockForever); err != nil {
		}
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	log.Println("reading in packets")
	assembler := (&assemblerFactory{}).New()

	if _, err := PathExists(fpath); err != nil {
		log.Fatal(err)
	}

	// Read in packets.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if *logAllPackets {
				log.Println(packet)
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}

			netlayer := packet.NetworkLayer()
			tcp := packet.TransportLayer().(*layers.TCP)

			if tcp != nil {
				if ip != nil {
					dst := netlayer.NetworkFlow().Dst().String()
					match := false
					for _, i := range ip {
						if dst == i {
							match = true
							break
						}
					}
					if !match {
						continue
					}
				}
				quad := fmt.Sprintf("%s[%s]-%s[%s]", netlayer.NetworkFlow().Src().String(), tcp.SrcPort.String(), netlayer.NetworkFlow().Dst().String(), tcp.DstPort.String())
				if ts, ok := assembler.poolmap[quad]; ok {
					if err := ts.w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
						log.Fatal(err)
					}
					ts.lastseen = time.Now()
				} else {
					// Open output pcap file and write header
					filename := fmt.Sprintf("%s-%s.pcap", quad, time.Now().Format("2006-01-02 15:04:05"))
					f, _ := os.Create(path.Join((*fpath), filename))
					w := pcapgo.NewWriter(f)
					err := w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
					if err != nil {
						continue
					}
					if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
						log.Fatal(err)
					}
					tcpstream := &tcpStream{f: f, w: w, lastseen: time.Now()}

					assembler.poolmap[quad] = tcpstream

					if *bidirection {
						quadNegative := fmt.Sprintf("%s[%s]-%s[%s]", netlayer.NetworkFlow().Dst().String(), tcp.DstPort.String(), netlayer.NetworkFlow().Src().String(), tcp.SrcPort.String())
						assembler.poolmap[quadNegative] = tcpstream
					}

				}
			}
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
