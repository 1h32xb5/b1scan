package main

import (
	"bufio"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"os"
	"os/exec"
)

func main() {
	//111
	//设置外壳的框
	myApp := app.New()
	myWindow := myApp.NewWindow("内网漏洞扫描系统")
	myWindow.Resize(fyne.NewSize(700, 450))
	input1 := widget.NewEntry()
	input1.SetPlaceHolder("eg:192.168.2.1/24")
	input2 := widget.NewEntry()
	input2.SetPlaceHolder("eg:whoami")

	button1 := widget.NewButton("ssh-Command execution", func() {
		input123:=input2.Text    //输入的框里面的hosts
		outputText1 := executeCommand("go run main.go sshattack -a "+input123) // 调用执行终端命令的函数，并获取其输出
		println(outputText1)      // 将输出设置到标签中显示
	})
	//创建一个容器 input2Container，将 input2 输入框放入其中
	input2Container := container.New(layout.NewGridWrapLayout(fyne.NewSize(500, input2.MinSize().Height)), input2)
	input2Container.Resize(input2Container.MinSize().Add(fyne.NewSize(100, 0))) // 设置容器的宽度为 100

	// 创建一个水平布局的容器中，并将 input1 和 button1 放入
	row2 := container.NewHBox(input2Container, button1)
	//按钮的作用
	//
	content := container.NewVBox(input1, widget.NewButton("C-segment host-info scan(eg 192.1.1.1/24", func() {      //点击一下按钮触发的作用
		Hosts:=input1.Text    //输入的框里面的hosts
		outputText := executeCommand("go run main.go ping -H "+Hosts) // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示
	}), widget.NewButton("port-scan", func() {
		Hosts:=input1.Text    //输入的框里面的hosts
		outputText := executeCommand("go run main.go portscan -H "+Hosts) // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示
	}), widget.NewButton("web-title scanning", func() {
		outputText := executeCommand("go run main.go info") // 调用执行终端命令的函数，并获取其输出
		println(outputText)
	}), widget.NewButton("web-Vulnerability scanning", func() {
		// 创建新窗口并将垂直容器设置为内容
		newWindow := myApp.NewWindow("New Window")              //每次点击web-Vulnerability scanning按钮都会创建一个新的窗口
		newWindow.Resize(fyne.NewSize(300, 250))

		// 创建两个新按钮和一个返回按钮
		button1 := widget.NewButton("oa-poc Attack", func() {
			outputText := executeCommand("go run main.go weboa") // 调用执行终端命令的函数，并获取其输出
			println(outputText)      // 将输出设置到标签中显示
		})
		button2 := widget.NewButton("cms-poc Attack", func() {
			outputText := executeCommand("go run main.go webcms") // 调用执行终端命令的函数，并获取其输出
			println(outputText)      // 将输出设置到标签中显示

		})
		button3 := widget.NewButton("thinkphp-poc Attack", func() {
			outputText := executeCommand("go run main.go webthinkphp") // 调用执行终端命令的函数，并获取其输出
			println(outputText)      // 将输出设置到标签中显示

		})
		backButton := widget.NewButton("Back", func() {
			// 关闭新窗口并返回到主窗口
			newWindow.Close()
		})

		// 将按钮放入垂直容器
		buttons := container.NewVBox(
			button1,
			button2,
			button3,
			backButton,
		)
		newWindow.SetContent(buttons)
		// 显示新窗口
		newWindow.Show()

	}), widget.NewButton("mysql-Brute force", func() {
		outputText := executeCommand("go run main.go mysql") // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示

	}), widget.NewButton("mssql-Brute force", func() {
		outputText := executeCommand("go run main.go mssql") // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示

	}), widget.NewButton("redis-Brute force", func() {
		outputText := executeCommand("go run main.go redis") // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示
	}), widget.NewButton("ssh-Brute force", func() {
		outputText := executeCommand("go run main.go ssh") // 调用执行终端命令的函数，并获取其输出
		println(outputText)      // 将输出设置到标签中显示
	}),
	row2,
	widget.NewButton("Ms17010-exploitation", func() {
	}),
	)
	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}


// executeCommand 函数用于执行终端命令，并返回其输出结果
func executeCommand(command string) string {
	println(command)
	cmd := exec.Command("sh", "-c", command) // 在Unix系统上执行终端命令
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	file, err := os.Create("1.txt")
	scanner := bufio.NewScanner(stdout)
	var output string
	for scanner.Scan() {
		output += scanner.Text() + "\n"
		_, err := file.WriteString(scanner.Text() + "\n")
		if err != nil {
			fmt.Println("写入文件失败:", err)
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return output
}