package cmd

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"os"
	"regexp"
	"time"
)

var abc []string
var user []string
var pwd []string
var ips []string

var sshattackCmd = &cobra.Command{
	Use:   "sshattack",
	Short: "ssh执行命令",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\033[1;31;40m%s\033[0m\n", "ssh执行命令")
		flag.Parse()

		//打开文件
		file, _ := os.Open("./ssh.txt")

		defer file.Close()
		// 创建一个 Scanner 以读取文件的内容
		scanner := bufio.NewScanner(file)

		// 逐行读取文件内容
		for scanner.Scan() {
			// 将每行添加到切片中
			abc = append(abc, scanner.Text())
		}
		for _, line := range abc {
			re := regexp.MustCompile(`ip:(.*?),user:(.*?),pwd:(.*?),`) // 定义正则表达式
			match := re.FindStringSubmatch(line)                        // 提取匹配的字符串
			if len(match) == 4 {
				ip := match[1]    //ip
				user := match[2]  //user
				pwd := match[3]   //pwd
				out1, err := sshattackLogin(Mingling,ip, user, pwd)
				if err != nil {
					fmt.Println("帐号和密码错误:", err)
					continue // 如果发生错误，跳过当前循环，继续下一次循环
				}
				fmt.Printf(ip+" 执行的结果："+out1)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(sshattackCmd)
	sshattackCmd.Flags().StringVarP(&Mingling, "mingling", "a", "", "设置你要执行的命令")
}

func sshattackLogin(Mingling,ip, username, password string) (string, error) {
	var result string

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         1 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", ip, 22), config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(Mingling)
	if err != nil {
		return "", err
	}
	result = string(output)
	return result, nil
}
