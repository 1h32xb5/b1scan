package cmd

import (
	"bufio"
	"demo/cmd/config"
	"demo/pkg/logger"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"

	"context"
	"github.com/go-redis/redis/v8"
	"sync"
	"time"
)

const (
	redisPort = "6379"
)

var redisCmd = &cobra.Command{
	Use:   "redis",
	Short: "对内网 Redis 数据库进行弱口令检测",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\033[1;31;40m%s\033[0m\n", "正在进行 Redis 数据库弱口令爆破...")
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
			if redisCheckAlive(ip) {
				aliveIps = append(aliveIps, ip)
			} else {
				fmt.Printf(ip + ":6379端口没打开" + "\n")
			}
		}
		// 输出相关端口打开的ip
		for _, ips := range aliveIps {
			fmt.Printf(ips + ":6379端口打开-------" + "\n")
		}

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
		for _, password := range passwords {
			for _, ip := range aliveIps {
				wg.Add(1)
				go func(ip, password string) {
					defer wg.Done()
					success := BruteRedis(password, ip)
					if success {
						result := fmt.Sprintf("破解%v成功，密码是%v\n", ip, password)
						results <- result
					} else {
						fmt.Printf("破解%v失败，密码是%v\n", ip, password)
					}
				}(ip, password)
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
	rootCmd.AddCommand(redisCmd)
	redisCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要扫描 Redis 数据库的主机")
}

func BruteRedis(password, ip string) bool {
	opt := &redis.Options{
		Addr:     ip + ":" + redisPort,
		Password: password,
	}
	client := redis.NewClient(opt)
	defer client.Close()

	ctx := context.Background()
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return false
	}
	return true
}

func redisCheckAlive(ip string) bool {
	alive := false
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, redisPort), 100*time.Millisecond)
	if err == nil {
		alive = true
	}
	return alive
}
