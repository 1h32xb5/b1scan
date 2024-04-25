package main
//Ladon Scanner for golang
//Author: k8gege
//K8Blog: http://k8gege.org/Ladon
//Github: https://github.com/k8gege/LadonGo
import (
	"encoding/binary"
	"io/ioutil"
	"strings"

	//"flag"
	"fmt"
	"net"
	//"sync"
	"time"
	//"runtime"

)



func main() {
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
}
