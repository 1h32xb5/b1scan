package cmd

import (
	"bufio"
	"crypto/tls"
	"demo/pkg/logger"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

var resp_title string
var response_body string
var body_bytes string
var redirect1_Url []string
var code int
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "一个全方位信息搜集的命令(主机存活/端口开放/webtitle信息)",
	Run: func(cmd *cobra.Command, args []string) {
		redirect_Url = make([]string, 0)
		start := time.Now()
		println(start.Second())
		//依此读取文件进入切片
		file, _ := os.Open("./outputip.txt")     //打开文件
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			SurvivalHost = append(SurvivalHost, line)
		}

		var wg sync.WaitGroup
		stringchan := make(chan string,200)


		for i:=0;i<len(SurvivalHost);i++{
			wg.Add(1)
			stringchan <- SurvivalHost[i]
		}
		for i:=0;i< 500;i++{
			go func ( ){
				a :=<- stringchan
				defer wg.Done()
				conn, _ := net.Dial("tcp", a)
				http_url := a + ":80"
				https_url :=a + ":443"
				timeout := 3 * time.Second
				conn, err := net.DialTimeout("tcp", http_url, timeout)
				if err == nil {
					// 如果连接成功，则添加HTTP重定向URL
					redirect1_Url := "http://" + a
					redirect_Url = append(redirect_Url, redirect1_Url)
					conn.Close() // 关闭连接
				} else {
					// 如果HTTP连接失败，则尝试HTTPS连接
					conn1, err := net.DialTimeout("tcp", https_url, timeout)
					if err == nil {
						// 如果HTTPS连接成功，则添加HTTPS重定向URL
						redirect1_Url := "https://" + a
						redirect_Url = append(redirect_Url, redirect1_Url)
						conn1.Close() // 关闭连接
					}
				}
				//conn, _ = net.Dial("tcp", http_url)
				//conn1, _ := net.Dial("tcp", https_url)
				//if conn != nil {
				//	redirect1_Url = "http://" + a
				//	redirect_Url = append(redirect_Url,redirect1_Url)
				//} else if conn1 != nil {
				//	redirect1_Url = "https://" + a
				//	redirect_Url = append(redirect_Url,redirect1_Url)
				//}
			}()
		}
		wg.Wait()
		tail()
		elapsed := time.Since(start)
		fmt.Println(elapsed)

		//////  写入url到文件中
		defer func() {
			//    把hostsurvial切片里面的ip输入到txt里面
			file, _ := os.Create("webtitle.txt")
			defer file.Close()
			// 遍历切片并将每个元素写入文件
			for a,_:=range redirect_Url{
				_, err := fmt.Fprintln(file, redirect_Url[a])
				if err != nil {
					fmt.Printf("failed to write to file: %v\n", err)
					return
				}
			}
			fmt.Println("写入webtitle.txt完成！")
		}()
		//////
	},
}
func tail(){
	for a,_:=range redirect_Url{
		request(a,redirect_Url,code,5)
		l:=fmt.Sprintf("[%d]",request(a,redirect_Url,code,3))
		fmt.Println(logger.Purple(l)+redirect_Url[a]+" [title:" + logger.Blue(resp_title)+"]")
	}
}
func init() {
	rootCmd.AddCommand(infoCmd)
	infoCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要全方位扫描的主机")     //起到的作用就是声明一个属于父命令的一个参数  但是不起实质作用
}
func request(i int,redirect_Url []string,code int,timeout int) int{
	defer func() {
		if r := recover(); r != nil {
		}
	}()
		client := &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport {
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse                //重定向
			},
		}
		request, _ := http.NewRequest("GET", redirect_Url[i], nil)
		resp, _ := client.Do(request)
		body_bytes, _ := ioutil.ReadAll(resp.Body)
		response_body = string(body_bytes)
		grep_title := regexp.MustCompile("<title>(.*)</title>")
		if len(grep_title.FindStringSubmatch(response_body)) != 0 {
			resp_title = grep_title.FindStringSubmatch(response_body)[1]
		} else {
			resp_title = "None"
		}
		code = resp.StatusCode
	return code
}

