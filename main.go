package main

import (
	"FDC-WeOne/dao"
	"FDC-WeOne/routers"
	"FDC-WeOne/tools"
	_ "github.com/gin-gonic/gin"
	"log"
	"os"
)

func init() {
	tools.GenerateRSAKey(2048)
	log.SetPrefix("server: ")
	file, err := os.OpenFile("./server.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalln(err)
	}
	log.SetOutput(file)
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)
}

//theTime := time.Now().Format(time.Layout)
//mySession := GetMD5Encode(master.Phone + master.Name + theTime)
//fmt.Println("登录态为： ", mySession, "时间为： ", theTime)

func main() {
	//初始化数据库链接
	daoErr := dao.InitDB()
	if daoErr != nil {
		log.Fatalln(daoErr)
	}

	// 设置请求路由
	r := routers.SetupRouter()

	// 监听并在 8080端口上启动服务
	err := r.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
