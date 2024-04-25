package cmd

import (
	"bufio"
	"demo/pkg/logger"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var weboaCmd = &cobra.Command{
	Use:   "weboa",
	Short: "cms-poc Attack",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\033[1;31;40m%s\033[0m\n", "正在进行对url进行oa-poc攻击")
		flag.Parse()
		start := time.Now()


		defer func() {
			elapsed := time.Since(start)
			fmt.Println(elapsed)
		}()

		dir := "cmd/poc/oapoc"
		files, _ := ioutil.ReadDir(dir)
		for _, file := range files {
			if filepath.Ext(file.Name()) == ".yml" || filepath.Ext(file.Name()) == ".yaml" {
				yamlFilePath := filepath.Join(dir, file.Name())
				yamlFile, _ := ioutil.ReadFile(yamlFilePath)	// 读取 YAML 文件
				var poc POC
				yaml.Unmarshal(yamlFile, &poc)       	// 解析 YAML 文件

				// 循环遍历规则进行验证
				for _, rule := range poc.Rules {                 //如过yaml中有多种rules则用这个

					file, _ := os.Open("./webtitle.txt")
					defer file.Close()
					scanner := bufio.NewScanner(file)			// 创建一个 Scanner 以读取文件的内容
					var abc []string
					for scanner.Scan() {							// 逐行读取文件内容
						abc = append(abc, scanner.Text())			// 将每行添加到切片中
					}


					for _, line := range abc {
						fullURL := line + rule.Path				    // 替换为要测试的目标网站的 URL
						client := &http.Client{}
						req, _ := http.NewRequest(rule.Method, fullURL+rule.Path, strings.NewReader(rule.Body))
						// 设置请求头
						for key, value := range rule.Headers {
							req.Header.Set(key, value)
						}
						// 发送 HTTP 请求
						resp, err := client.Do(req)
						if err != nil {
							fmt.Println("URL:"+line+"网站访问异常:网站301")
							continue
						}
						defer resp.Body.Close()
						// 读取响应内容
						body, _ := ioutil.ReadAll(resp.Body)

						//检查响应是否包含预期的表达式
						if strings.Contains(string(body), rule.Expression) {
							a:=fmt.Sprintf("URL:%s-----------------存在%s\n",line,poc.Name)
							fmt.Printf(logger.LightBlue(a))
						} else {
							fmt.Printf("URL:%s-不存在%s\n",line,poc.Name)
						}
					}
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(weboaCmd)
	weboaCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "设置你要扫描 Redis 数据库的主机")
}