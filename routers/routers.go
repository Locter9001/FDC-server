package routers

import (
	"FDC-WeOne/controllers"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

//Verify 验证中间件，所有请求都需要通过验证，即token验证
func Verify() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("1")
		//c.Next()
		fmt.Println("2")
	}
}

func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(Verify())
	r.StaticFS("/src", http.Dir("./src/"))
	liangApi := r.Group("/liang-api")
	{
		master := liangApi.Group("/master")
		{ //管理员权限
			master.POST("/login", controllers.MasterLogin)                     //员工登录  ok2
			master.GET("/fast-login", controllers.FastLogin)                   //使用登录态快速登录
			master.POST("/signup", controllers.MasterSignUp)                   //员工注册  ok2
			master.POST("/insertGoods/:token", controllers.InsertGoods)        //新增楼盘 ok
			master.GET("/refresh-token/:token", controllers.RefreshToken)      //刷新token ok
			master.GET("/get-goods/:token", controllers.GetAdminGoods)         //获取管理员版所有房产信息 ok
			master.POST("/upfile", controllers.UploadFile)                     //上传文件 ok
			master.POST("/report/:token", controllers.Report)                  //新增报备 ok
			master.GET("/look-report/:token", controllers.LookReport)          //带看接口
			master.POST("/add-custom/:token", controllers.AddCustomer)         //新增客户 ok
			master.GET("/get-all-costomer/:token", controllers.GetALlCostomer) //获取客户列表
			admin := master.Group("/admin")
			{
				admin.GET("/pass-report/:token", controllers.PassReport)                     //报备通过 ok
				admin.GET("/ok-report/:token", controllers.ReportEnd)                        //成交 ok
				admin.POST("/update-master/:token", controllers.UpdateMaster)                //新增员工 ok
				admin.GET("/add-master/:token", controllers.AddMaster)                       //新增员工
				admin.GET("/get-all-master/:token", controllers.GetAllMaster)                //获取所有master用户 ok
				admin.GET("/get-all-report/:token", controllers.GetAllReports)               //获取申请的报备列表 ok
				admin.GET("/get-all-signup-masters/:token", controllers.GetALLSignUpMasters) //获取所有申请注册的用户
			}
		}

		user := liangApi.Group("/user")
		{ //用户操作
			//user.POST("/login", controllers.Login)       //登录
			user.GET("/SMScode", controllers.GetSMScode) //获取短信验证码
		}

	}

	return r
}
