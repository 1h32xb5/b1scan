package cmd

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"strings"
	"time"
)
var (
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

var ms17010Cmd = &cobra.Command{
	Use:   "ms17010",
	Short: "检测ms17010漏洞",
	Run: func(cmd *cobra.Command, args []string) {

		file, _ := os.Open("./outputip.txt")
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			SurvivalHost = append(SurvivalHost, line)
		}
		for _, ip := range SurvivalHost {
			conn, err := net.DialTimeout("tcp", ip+":445", 2*time.Second)
			if err != nil {
				fmt.Printf("%s\t445端口未开启\n", ip)
				continue // 端口未开启，跳出当前循环，继续处理下一个主机
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write(negotiateProtocolRequest)
			reply := make([]byte, 1024)
			// let alone half packet
			if n, err := conn.Read(reply); err != nil || n < 36 {
				fmt.Printf("%s没有漏洞\n", ip)
			}

			if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
				// status != 0
				return
			}

			conn.Write(sessionSetupRequest)

			n, err := conn.Read(reply)
			if err != nil || n < 36 {
				return
			}
			if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
				return
			}

			var os string
			sessionSetupResponse := reply[36:n]
			if wordCount := sessionSetupResponse[0]; wordCount != 0 {
				// find byte count
				byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
				if n != int(byteCount)+45 {
					fmt.Println("invalid session setup AndX response")
				} else {
					// two continous null bytes indicates end of a unicode string
					for i := 10; i < len(sessionSetupResponse)-1; i++ {
						if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
							os = string(sessionSetupResponse[10:i])
							os = strings.Replace(os, string([]byte{0x00}), "", -1)
							break
						}
					}
				}
			}
			userID := reply[32:34]
			treeConnectRequest[32] = userID[0]
			treeConnectRequest[33] = userID[1]
			// TODO change the ip in tree path though it doesn't matter
			conn.Write(treeConnectRequest)

			if n, err := conn.Read(reply); err != nil || n < 36 {
				return
			}
			treeID := reply[28:30]
			transNamedPipeRequest[28] = treeID[0]
			transNamedPipeRequest[29] = treeID[1]
			transNamedPipeRequest[32] = userID[0]
			transNamedPipeRequest[33] = userID[1]
			conn.Write(transNamedPipeRequest)
			if n, err := conn.Read(reply); err != nil || n < 36 {
				return
			}
			if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 { //则说明远程主机可能存在 MS17-010 漏洞
				//这段代码用于检查 SMB 会话协商响应中的状态码，以确定远程主机是否存在 MS17-010 漏洞。具体来说，它检查 SMB 会话协商响应的第 9、10、11、12 字节是否满足以下条件：
				//
				//reply[9] == 0x05：表示 SMB 会话协商响应中的状态码为 0x05，这对应于 NT 状态码 STATUS_BAD_NETWORK_NAME。这个状态码表示请求的网络名称无效或找不到。
				//reply[10] == 0x02：表示 SMB 会话协商响应中的标识符为 0x02，这对应于 SMBv2 协议。
				//reply[11] == 0x00：表示 SMB 会话协商响应中的 Windows 版本为 0x00，这通常对应于 Windows 2000 或更早版本。
				//reply[12] == 0xc0：表示 SMB 会话协商响应中的 Windows 平台 ID 为 0xc0，这通常对应于 Windows 2000 工作站或服务器。
				//如果以上条件全部满足，则说明远程主机可能存在 MS17-010 漏洞。在这种情况下，通常会继续执行后续的攻击步骤或者进行其他的安全评估。
				fmt.Print("Find:" + ip + "\t存在MS17-010\t" + os + "\n")
			} else {
				fmt.Print( ip + "\t不存在MS17-010\t" + os + "\n")
			}
		}
	},
}


func init() {
	rootCmd.AddCommand(ms17010Cmd)
	ms17010Cmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要ssh弱口令爆破的主机")
}