package tracee

import (
	"encoding/binary"
	"net"
	"strconv"
)

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable lenth slice, but that would case unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

// PrintAlert prints the encoded alert message and output file path if required
func PrintAlert(alert alert) string {
	var res string

	var securityAlerts = map[uint32]string{
		1: "Mmaped region with W+E permissions!",
		2: "Protection changed to Executable!",
		3: "Protection changed from E to W+E!",
		4: "Protection changed from W+E to E!",
	}

	if msg, ok := securityAlerts[alert.Msg]; ok {
		res = msg
	} else {
		res = strconv.Itoa(int(alert.Msg))
	}

	if alert.Payload != 0 {
		res += " Saving data to bin." + strconv.Itoa(int(alert.Ts))
	}

	return res
}

// ParseSocketTcpState parses the ........
func ParseSocketTcpState(socketState uint32) string {
	var socketStates = map[uint32]string{
		1:  "TCP_ESTABLISHED",
		2:  "TCP_SYN_SENT",
		3:  "TCP_SYN_RECV",
		4:  "TCP_FIN_WAIT1",
		5:  "TCP_FIN_WAIT2",
		6:  "TCP_TIME_WAIT",
		7:  "TCP_CLOSE",
		8:  "TCP_CLOSE_WAIT",
		9:  "TCP_LAST_ACK",
		10: "TCP_LISTEN",
		11: "TCP_CLOSING",
		12: "TCP_NEW_SYN_RECV",
	}
	var res string
	if socketStateName, ok := socketStates[socketState]; ok {
		res = socketStateName
	} else {
		res = strconv.Itoa(int(socketState))
	}
	return res
}
