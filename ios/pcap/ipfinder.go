package pcap

import (
	"context"
	"fmt"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type NetworkInfo struct {
	Mac  string
	IPv4 string
	IPv6 string
}

func (n NetworkInfo) complete() bool {
	return n.IPv6 != "" && n.Mac != "" && n.IPv4 != ""
}

// FindIp reads pcap packets until one is found that matches the given MAC
// and contains an IP address. This won't work if the iOS device "automatic Wifi address" privacy
// feature is enabled. The MAC needs to be static.
func FindIp(device ios.DeviceEntry) (NetworkInfo, error) {
	mac, err := ios.GetWifiMac(device)
	if err != nil {
		return NetworkInfo{}, err
	}
	return findIp(device, mac)
}

// FindIpWithTimeout reads pcap packets until one is found that matches the given MAC
// and contains an IP address, with a timeout. Returns partial results if timeout is reached.
// This won't work if the iOS device "automatic Wifi address" privacy feature is enabled.
func FindIpWithTimeout(device ios.DeviceEntry, timeout time.Duration) (NetworkInfo, error) {
	mac, err := ios.GetWifiMac(device)
	if err != nil {
		return NetworkInfo{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return findIpWithContext(ctx, device, mac)
}

func findIpWithContext(ctx context.Context, device ios.DeviceEntry, mac string) (NetworkInfo, error) {
	intf, err := ios.ConnectToService(device, "com.apple.pcapd")
	if err != nil {
		return NetworkInfo{}, err
	}
	defer intf.Close()

	plistCodec := ios.NewPlistCodec()
	info := NetworkInfo{}
	info.Mac = mac

	type packetResult struct {
		data []byte
		err  error
	}

	for {
		resultCh := make(chan packetResult, 1)

		go func() {
			b, err := plistCodec.Decode(intf.Reader())
			resultCh <- packetResult{data: b, err: err}
		}()

		select {
		case <-ctx.Done():
			if info.IPv4 != "" || info.IPv6 != "" {
				return info, nil
			}
			return info, fmt.Errorf("timeout waiting for IP address, ensure device has network traffic and 'Private Wi-Fi Address' is disabled")
		case result := <-resultCh:
			if result.err != nil {
				return NetworkInfo{}, result.err
			}
			decodedBytes, err := fromBytes(result.data)
			if err != nil {
				return NetworkInfo{}, err
			}
			_, packet, err := getPacket(decodedBytes)
			if err != nil {
				return NetworkInfo{}, err
			}
			if len(packet) > 0 {
				err := findIP(packet, &info)
				if err != nil {
					return NetworkInfo{}, err
				}
				if info.complete() {
					return info, nil
				}
			}
		}
	}
}

func findIp(device ios.DeviceEntry, mac string) (NetworkInfo, error) {
	intf, err := ios.ConnectToService(device, "com.apple.pcapd")
	if err != nil {
		return NetworkInfo{}, err
	}
	plistCodec := ios.NewPlistCodec()
	info := NetworkInfo{}
	info.Mac = mac
	for {
		b, err := plistCodec.Decode(intf.Reader())
		if err != nil {
			return NetworkInfo{}, err
		}
		decodedBytes, err := fromBytes(b)
		if err != nil {
			return NetworkInfo{}, err
		}
		_, packet, err := getPacket(decodedBytes)
		if err != nil {
			return NetworkInfo{}, err
		}
		if len(packet) > 0 {
			err := findIP(packet, &info)
			if err != nil {
				return NetworkInfo{}, err
			}
			if info.complete() {
				return info, nil
			}
		}
	}
}

func findIP(p []byte, info *NetworkInfo) error {
	packet := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeEthernet); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.Ethernet)
		if tcp.SrcMAC.String() == info.Mac {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.Debugf("found packet for %s", info.Mac)
				for _, layer := range packet.Layers() {
					log.Debugf("layer:%s", layer.LayerType().String())
				}
			}
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, ok := ipv4Layer.(*layers.IPv4)
				if ok {
					info.IPv4 = ipv4.SrcIP.String()
					log.Debugf("ip4 found:%s", info.IPv4)
				}
			}
			if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
				ipv6, ok := ipv6Layer.(*layers.IPv6)
				if ok {
					info.IPv6 = ipv6.SrcIP.String()
					log.Debugf("ip6 found:%s", info.IPv6)
				}
			}
		}
	}
	return nil
}
