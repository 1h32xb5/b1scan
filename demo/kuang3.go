package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ReqHttp struct {
	ReqMethod string
	ReqPath   string
	ReqHeader []string
	ReqBody   string
}

type InStr struct {
	InBody   string
	InHeader string
	InIcoMd5 string
}

type RuleLab struct {
	Rank int
	Name string
	Type string
	Mode string
	Rule InStr
	Http ReqHttp
}

var RuleData = []RuleLab{
	{1, "08CMS", "body", "", InStr{"content=\"08cms|typeof(_08cms)", "", ""}, ReqHttp{"", "", nil, ""}},
	{1, "1039soft-JiaXiao", "body", "", InStr{"name=\"hid_qu_type\" id=\"hid_qu_type\"|/handler/validatecode.ashx?id=", "", ""}, ReqHttp{"", "", nil, ""}},
	{1, "17mail", "body", "", InStr{"//易企邮正式版发布", "", ""}, ReqHttp{"", "", nil, ""}},
	{1, "3dusoft-eSalerSalesSystem", "body", "", InStr{"(青岛叁度信息技术有限公司)", "", ""}, ReqHttp{"", "", nil, ""}},
	{1, "3KITS-CMS", "body", "", InStr{"(href=\"http://www.3kits.com\")", "", ""}, ReqHttp{"", "", nil, ""}},
	{1, "42Gears-SureMDM", "body", "", InStr{"(suremdm|astrocontacts)", "", ""}, ReqHttp{"", "", nil, ""}},
	{3, "ThinkPHP", "body|header|ico", "or", InStr{"(href=\"http://www.thinkphp.cn\">ThinkPHP</a>|十年磨一剑-为API开发设计的高性能框架)", "(thinkphp|think_template)", "(f49c4a4bde1eec6c0b80c2277c76e3db)"}, ReqHttp{"", "", nil, ""}},
	{1, "ThinkPHP-YFCMF", "body", "", InStr{"(yfcmf|/public/others/maxlength.js|/yfcmf/yfcmf.js)", "", ""}, ReqHttp{"", "", nil, ""}},
	// 其他规则...
}

// ScanIPs 扫描IP地址列表并进行Web指纹识别
func ScanIPs(ips []string) {
	for _, ip := range ips {
		for _, rule := range RuleData {
			// 构建HTTP请求
			req, err := http.NewRequest(rule.Http.ReqMethod, fmt.Sprintf("%s%s", ip, rule.Http.ReqPath), nil)
			if err != nil {
				fmt.Printf("IP: %s, 规则: %s, 匹配失败\n", ip, rule.Name)
				continue
			}

			// 发送HTTP请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("IP: %s, 规则: %s, 匹配失败\n", ip, rule.Name)
				continue
			}
			defer resp.Body.Close()

			// 读取响应体
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("IP: %s, 规则: %s, 匹配失败\n", ip, rule.Name)
				continue
			}
			body := string(bodyBytes)

			// 检查规则匹配
			bodyMatch := strings.Contains(body, rule.Rule.InBody)
			headerMatch := strings.Contains(strings.Join(rule.Http.ReqHeader, ""), rule.Rule.InHeader)
			icoMd5Match := strings.Contains(rule.Name, rule.Rule.InIcoMd5)

			if bodyMatch || headerMatch || icoMd5Match {
				fmt.Printf("IP: %s, 规则: %s, 匹配成功\n", ip, rule.Name)
				break
			}
		}
	}
}

func main() {
	var SurvivalHost []string
	// 依次读取文件进入切片
	file, err := os.Open("./webtitle.txt")
	if err != nil {
		fmt.Printf("打开文件失败：%v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		SurvivalHost = append(SurvivalHost, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("读取文件失败：%v\n", err)
		return
	}

	ScanIPs(SurvivalHost) //执行扫描
}
