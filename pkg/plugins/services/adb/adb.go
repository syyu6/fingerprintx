package adb

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type ADBPlugin struct{}

const ADB = "adb"

var (
	commonADBPorts = map[int]struct{}{
		5005: {},
		5555: {},
	}
)

func init() {
	plugins.RegisterPlugin(&ADBPlugin{})
}

// ##############################NEXT PROBE##############################
// # Android Debug Bridge CONNECT probe
// # https://android.googlesource.com/platform/system/core/+/master/adb/protocol.txt
// Probe TCP adbConnect q|CNXN\0\0\0\x01\0\x10\0\0\x07\0\0\0\x32\x02\0\0\xbc\xb1\xa7\xb1host::\0|
// rarity 8
// ports 5555

// match adb m|^CNXN\0\0\0\x01\0\x10\0\0........\xbc\xb1\xa7\xb1(\w+)::ro.product.name=([^;]+);ro.product.model=([^;]+);ro.product.device=([^;]+);\0$|s p/Android Debug Bridge $1/ i/name: $2; model: $3; device: $4/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a
// match adb m|^CNXN\0\0\0\x01\0\x10\0\0........\xbc\xb1\xa7\xb1(\w+)::ro.product.name=([^;]+);ro.product.model=([^;]+);ro.product.device=([^;]+);features=([^\0]+)$|s p/Android Debug Bridge $1/ i/name: $2; model: $3; device: $4; features: $5/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a

// match adb m|CNXN\0\0\0\x01\0\x10\0\0\t\0\0\0\xe4\x02\0\0\xbc\xb1\xa7\xb1device::\0$| p/Android Debug Bridge device/ i/no auth/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a
// # If it has identifying info, softmatch so we can make a better fingerprint
// softmatch adb m|^CNXN\0\0\0\x01\0\x10\0\0........\xbc\xb1\xa7\xb1(\w+):[^:]*:[^\0]+\0$|s p/Android Debug Bridge $1/ i/no auth/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a

// match adb m|^AUTH\x01\0\0\0\0\0\0\0........\xbc\xb1\xa7\xb1|s p/Android Debug Bridge/ i/token auth required/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a
// softmatch adb m|^AUTH(.)\0\0\0\0\0\0\0........\xbc\xb1\xa7\xb1|s p/Android Debug Bridge/ i/auth required: $I(1,"<")/ o/Android/ cpe:/o:google:android/a cpe:/o:linux:linux_kernel/a

//	if requestName == "TCP_adbConnect" && finger.Service == "" {
//		if (strings.HasPrefix(responseRaw, "CNXN\x01\x00\x00\x01\x00\x10\x00") || strings.HasPrefix(responseRaw, "AUTH\x01\x00\x00\x01\x00\x10\x00")) &&
//			strings.Contains(responseRaw, "\xbc\xb1\xa7\xb1") {
//			return &FingerPrint{
//				ProbeName: requestName,
//				Service:   "adb",
//			}
//		}
//	}
func (p *ADBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	requestBytes := []byte{
		// adb connect
		// CNXN\0\0\0\x01\0\x10\0\0\x07\0\0\0\x32\x02\0\0
		0x43, 0x4e, 0x58, 0x4e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32, 0x02, 0x00, 0x00,
		// 0xbc\xb1\xa7\xb1host::\0
		0xbc, 0xb1, 0xa7, 0xb1, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x3a, 0x00,
	}

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	// log.Printf("[-] adb send data completed")
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		log.Printf("[-] adb response null")

		return nil, nil
	}

	// response 转字符串
	responseRaw := string(response)
	// log.Println("response:", responseRaw)
	// log.Println("target:", target)
	if (strings.HasPrefix(responseRaw, "CNXN\x01\x00\x00\x01\x00\x10\x00") || strings.HasPrefix(responseRaw, "AUTH\x01\x00\x00\x01\x00\x10\x00")) && strings.Contains(responseRaw, "\xbc\xb1\xa7\xb1") {
		return plugins.CreateServiceFrom(target, plugins.ServiceADB{}, false, "", plugins.TCP), nil
	} else {
		log.Println("match null ")
		return nil, nil
	}

}

func (p *ADBPlugin) PortPriority(port uint16) bool {
	_, ok := commonADBPorts[int(port)]
	return ok
}

func (p *ADBPlugin) Name() string {
	return ADB
}

func (p *ADBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ADBPlugin) Priority() int {
	return 500
}
