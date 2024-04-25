package cmd

import (
	"bufio"
	"database/sql"
	"demo/cmd/config"
	"demo/pkg/logger"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/spf13/cobra"
	"net"
	"os"
	"sync"
	"time"

	"strings"
)

const (
	port = "3306"
	dbName = "information_schema"            //数据库 名字  下面打开这个数据库     information_schema
)

var mysqlCmd = &cobra.Command{
	Use:   "mysql",
	Short: "对内网mysql数据库进行弱口令检测",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\033[1;31;40m%s\033[0m\n", "正在进行mysql数据库弱口令爆破...")
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
			if mysqlcheckAlive(ip) {
				aliveIps = append(aliveIps, ip)
			} else {
				fmt.Printf(ip + ":3306端口没打开"+"\n")
			}
		}
		// 输出相关端口打开的ip
		for _, ips := range aliveIps {
			fmt.Printf(ips + ":3306端口打开-------"+"\n")
		}

		users := config.Userdict["mysql"]
		passwords := config.Passwords

		var wg sync.WaitGroup
		results := make(chan string)

		// 处理结果的协程
		go func() {
			for res := range results {
				fmt.Println(logger.LightBlue(res))
			}
		}()

		// 创建协程进行爆破

		// 创建协程进行爆破
		for _, user := range users {
			for _, password := range passwords {
				for _, ip := range aliveIps {
					wg.Add(1)
					go func(ip, user, password string) {
						defer wg.Done()
						success := Burtemysql(user,password,ip)
						if success {
							result := fmt.Sprintf("破解%v成功，用户名是%v,密码是%v\n", ip, user, password)
							results <- result
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
	rootCmd.AddCommand(mysqlCmd)
	mysqlCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要扫描mysqld爆破的主机")
}

func Burtemysql(user string,password string,ip string) bool{
	var DB *sql.DB
	path:=strings.Join([]string{user, ":", password, "@tcp(",ip, ":", port, ")/", dbName, "?charset=utf8"}, "")
	DB, _ = sql.Open("mysql", path)
	DB.SetConnMaxLifetime(5)
	DB.SetMaxIdleConns(5)
	if err := DB.Ping(); err != nil{           //连接数据库 验证连接
		return false
	}else {
		return true
	}
}



func mysqlcheckAlive(ip string) bool {
	alive := false
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, "3306"), 100 * time.Millisecond)
	if err == nil {
		alive = true
	}
	return alive
}