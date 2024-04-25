package cmd

import (
	"bufio"
	"demo/cmd/config"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"sync"
	"time"
)

var (
	openports   []int
	closedports []int
)

var portscanCmd = &cobra.Command{
	Use:   "portscan",
	Short: "基于host主机的相应端口开放扫描",
	Run: func(cmd *cobra.Command, args []string) {
		Portscan()
	},
}

func init() {
	rootCmd.AddCommand(portscanCmd)
	portscanCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要扫描端口 开放的主机")
}

func Portscan() {
	file, _ := os.Open("./outputip.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		SurvivalHost = append(SurvivalHost, line)
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	// 设置并发数
	concurrency := 1000
	semaphore := make(chan struct{}, concurrency)

	// 启动goroutine扫描端口
	for _, ip := range SurvivalHost {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			for _, port := range config.DefaultPorts {
				semaphore <- struct{}{} // 控制并发数
				go func(ip string, port int) {
					defer func() { <-semaphore }()
					address := fmt.Sprintf("%s:%d", ip, port)
					conn, err := net.DialTimeout("tcp", address, 1*time.Second)
					if err != nil {
						mutex.Lock()
						closedports = append(closedports, port)
						mutex.Unlock()
						return
					}
					conn.Close()
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					mutex.Lock()
					fmt.Printf(ip+":%d Open\n", port)
					mutex.Unlock()
				}(ip, port)
			}
		}(ip)
	}
	wg.Wait()
}
