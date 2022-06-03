package controllers

import (
	"FDC-WeOne/dao"
	"FDC-WeOne/structs"
	"FDC-WeOne/tools"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

var (
	Secret     = "dong_tech" // 加盐
	ExpireTime = 3600        // token有效期
)

type verify struct {
	Name       int   `json:"name"`
	Power      int8  `json:"power"`
	VerifyTime int64 `json:"verifyTime"`
}

type SliceMock struct {
	addr uintptr
	len  int
	cap  int
}

const (
	ErrorreasonServerbusy = "服务器繁忙"
	ErrorreasonRelogin    = "请重新登陆"
)

//func Login(c *gin.Context) {
//	var data structs.VerifyStruct
//	err := c.ShouldBindJSON(&data)
//
//	//验证账号密码 && 验证用户注册
//	password, err := dao.VerifyLogin(data.Phone)
//	if password != data.Psw || err != nil {
//		c.JSON(http.StatusForbidden, gin.H{"code": 9007})
//		log.Println(err)
//		return
//	}
//	//获取openid、
//	wxLoginResp, err := tools.GetOpenid(data.Code)
//	if err != nil {
//		c.JSON(http.StatusBadGateway, gin.H{"code": 9002})
//		return
//	}
//
//	session := sessions.Default(c)
//	session.Set("openid", wxLoginResp.OpenId)
//	session.Set("sessionKey", wxLoginResp.SessionKey)
//
//	// 这里用openid和sessionkey的串接 进行MD5之后作为该用户的自定义登录态
//	mySession := GetMD5Encode(wxLoginResp.OpenId + wxLoginResp.SessionKey)
//
//	user, tag, err := dao.QuerryUser(data.Phone)
//	if err != nil {
//		c.JSON(http.StatusNotFound, gin.H{"code": 9004})
//		log.Println(err)
//		return
//	}
//
//	//加密用户信息
//	claims := &structs.JWTClaims{
//		Userphone:    password,
//		Username:    user.Phone,
//		Permissions: tag,
//	}
//	claims.IssuedAt = time.Now().Unix()
//	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()
//
//	//获取token令牌
//	token, err := getToken(claims)
//	if err != nil {
//		c.JSON(http.StatusNotFound, gin.H{"code": 9003})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{
//		"code":         200,
//		"user":         user,
//		"token":        token,
//		"tag":          float64(tag) * 3.14,
//		"_3rd_session": mySession,
//	})
//}

func MasterLogin(c *gin.Context) {
	var data structs.VerifyStruct
	err := c.ShouldBindJSON(&data)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		log.Println("JSON校验失败 | 原因：非法字符 | ", err)
		return
	}

	fmt.Println(data)

	//获取保存的验证码
	vcode, err := dao.GetVCode(data.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
		log.Println("验证码获取 | 状态：失败 | ", err)
		return
	}

	//校验验证码
	if vcode != data.Code {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9007})
		log.Println("验证码校验 | 状态：失败 | ", err)
		return
	}

	//获取管理员信息
	master, err := dao.QuerryMaster(data.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9004})
		log.Println("查找当前用户 | 状态：失败 | ", err)
		return
	}
	//编辑用户注册时间
	cstSh, err := time.LoadLocation("Asia/Shanghai") //上海
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
		log.Println("生成注册时间 | 状态：失败 | ", err)
		return
	}
	theTime := time.Now().In(cstSh).Unix() + 86400*30
	//生成登录态并保存
	text := fmt.Sprintf(`{"name":%v,"power":%v,"verifyTime":%v}`, master.Phone, master.Power, theTime)
	fmt.Println(text)
	//生成登录态
	cipherText := tools.RsaEncrypt([]byte(text), "public.pem")
	encodeData := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println("加密后的登录态为：", cipherText)

	err = dao.PutAdminVerify(theTime, master.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9009})
		log.Println("保存登录态失败", err)
		return
	}
	//更新返回的登录态
	master.Verify = theTime
	//加密用户信息
	claims := &structs.JWTClaims{
		Username:    master.Name,
		Userphone:   master.Phone,
		Permissions: master.Power,
	}
	fmt.Printf("用户权限： %v", claims)
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()

	//获取token令牌
	Token, err := getToken(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9003})
		log.Println("token生成失败 | ", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":     200,
		"userInfo": master,
		"token":    Token,
		"verify":   encodeData,
	})
}

//FastLogin 使用登录态快速登录
func FastLogin(c *gin.Context) {
	WebContent := c.Query("verify")
	var verify verify
	// 解密字符串，对加密后的字符串进行解密，返回值是解密后的数据（byte数组形式）
	decodeDataByteArr, err := base64.StdEncoding.DecodeString(WebContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
		log.Println("base64解密失败 | ", err)
		return
	}
	plainText, err := tools.RsaDecrypt(decodeDataByteArr, "private.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
		log.Println("RSA解密失败 | ", err)
		return
	}
	err = json.Unmarshal(plainText, &verify)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
		log.Println("内容验证失败 | ", err)
		return
	}

	//检验登录态
	// 方法二
	cstSh, err := time.LoadLocation("Asia/Shanghai") //上海
	if err != nil {
		fmt.Println(err)
		return
	}
	theTime := time.Now().In(cstSh).Unix()
	if theTime > verify.VerifyTime {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9010})
		log.Println("登录态过期 | ")
		return
	}

	//获取管理员信息
	master, err := dao.QuerryMaster(strconv.Itoa(verify.Name))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9004})
		log.Println("查找当前用户 | 状态：失败 | ", err)
		return
	}
	//加密用户信息
	claims := &structs.JWTClaims{
		Username:    master.Name,
		Userphone:   master.Phone,
		Permissions: master.Power,
	}
	fmt.Printf("用户权限： %v", claims)
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()

	//获取token令牌
	Token, err := getToken(claims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9003})
		log.Println("token生成失败 | ", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":     200,
		"userInfo": master,
		"token":    Token,
	})
}

//MasterSignUp 员工注册
func MasterSignUp(c *gin.Context) {
	var master structs.Master
	err := c.ShouldBindJSON(&master)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		log.Println("JSON校验失败 | 原因：非法字符 | ", err)
		return
	}
	//使用Validate验证
	validate := validator.New()
	fmt.Println(master)
	err = validate.Struct(master)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
		return
	}

	//获取保存的验证码
	vcode, err := dao.GetVCode(master.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
		log.Println("验证码获取 | 状态：失败 | ", err)
		return
	}

	//校验验证码
	if vcode != master.SMSCode {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9007})
		log.Println("验证码校验 | 状态：失败 | ", err)
		return
	}

	//查询用户是否注册
	err = dao.VerifyMaster(master.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9005})
		log.Println("验证码校验 | 状态：失败 | ", err)
		return
	}

	//编辑用户注册时间
	cstSh, err := time.LoadLocation("Asia/Shanghai") //上海
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
		log.Println("生成注册时间 | 状态：失败 | ", err)
		return
	}
	theTime := time.Now().In(cstSh).Format("2006-01-02 15:04:05")
	master.SignTime = theTime

	//保存用户注册信息
	err = dao.PutMasterSignUpInfo(master)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
		log.Println("保存注册用户信息 | 状态：失败 | ", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 200,
	})
}

//GetALLSignUpMasters 获取所有申请注册的客户
func GetALLSignUpMasters(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	if claim.Permissions < 2 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}
	list, err := dao.GetAllMasterSignUpList(0)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9006})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"masters": list,
	})
}

//func QuickLogin(c *gin.Context) {
//	code := c.PostForm("code")
//	if code == "" {
//		c.JSON(http.StatusNotFound, gin.H{"code": 9000})
//		return
//	}
//	wxLoginResp, err := tools.GetOpenid(code)
//	if err != nil {
//		c.JSON(http.StatusBadGateway, gin.H{"code": 9002})
//		return
//	}
//
//	session := sessions.Default(c)
//	session.Set("openid", wxLoginResp.OpenId)
//	session.Set("sessionKey", wxLoginResp.SessionKey)
//
//	// 这里用openid和sessionkey的串接 进行MD5之后作为该用户的自定义登录态
//	mySession := GetMD5Encode(wxLoginResp.OpenId + wxLoginResp.SessionKey)
//	user, tag, err := dao.QuerryUser(wxLoginResp.OpenId)
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9004})
//		return
//	}
//	//加密用户信息
//	claims := &structs.JWTClaims{
//		Password:    user.Openid,
//		Username:    user.Phone,
//		Permissions: tag,
//	}
//	fmt.Printf("用户权限： %v", claims)
//	claims.IssuedAt = time.Now().Unix()
//	claims.ExpiresAt = time.Now().Add(time.Second * time.Duration(ExpireTime)).Unix()
//
//	//获取token令牌
//	signedToken, err := getToken(claims)
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9003})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{
//		"code":         200,
//		"user":         user,
//		"token":        signedToken,
//		"tag":          float64(tag) * 3.14,
//		"_3rd_session": mySession,
//	})
//}

//getToken 生成token
func getToken(claims *structs.JWTClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(Secret))
	if err != nil {
		return "", errors.New(ErrorreasonServerbusy)
	}
	return signedToken, nil
}

//RefreshToken 刷新token
func RefreshToken(c *gin.Context) {
	strToken := c.Param("token")
	claims, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	claims.ExpiresAt = time.Now().Unix() + (claims.ExpiresAt - claims.IssuedAt)
	signedToken, err := getToken(claims)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	c.String(http.StatusOK, signedToken)
}

//验证token
func verifyAction(strToken string) (*structs.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(strToken, &structs.JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(Secret), nil
	})
	if err != nil {
		return nil, errors.New(ErrorreasonServerbusy)
	}
	claims, ok := token.Claims.(*structs.JWTClaims)
	if !ok {
		return nil, errors.New(ErrorreasonRelogin)
	}
	if err := token.Claims.Valid(); err != nil {
		return nil, errors.New(ErrorreasonRelogin)
	}
	fmt.Println("verify")
	return claims, nil
}

func GetSMScode(c *gin.Context) {
	phone := c.Query("phone")
	// 生成6位随机数
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	vcode := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	_ = tools.SMSRequest(phone, vcode)
	dao.PutVCode(phone, vcode)
}

//func SignUp(c *gin.Context) {
//	var sign structs.SignUp
//	err := c.ShouldBindJSON(&sign)
//	if err != nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
//		return
//	}
//	// 使用Validate验证
//	validate := validator.New()
//	err = validate.Struct(sign)
//	if err != nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
//		return
//	}
//	//校验通过，查询是否有此用户
//	_, _, err = dao.QuerryUser(sign.Phone)
//	if err == nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9005})
//		return
//	}
//	//获取保存的验证码
//	vcode, err := dao.GetVCode(sign.Phone)
//	fmt.Printf("前：%s, %v | 后：%s, %v", sign.SMScode, sign.SMScode, vcode, vcode)
//	if err != nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
//		return
//	}
//	//校验验证码
//	if vcode != sign.SMScode {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9007})
//		return
//	}
//	//获取openid
//	wxResp, err := tools.GetOpenid(sign.Code)
//	if err != nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9002})
//		return
//	}
//
//	//创建用户
//	var user structs.User
//	user.Name = sign.Phone
//	user.Avatar = ""
//	user.Phone = sign.Phone
//	user.Openid = wxResp.OpenId
//	user.Password = sign.Password
//	err = dao.PutUserInfo(&user)
//	if err != nil {
//		fmt.Println(err)
//		c.JSON(http.StatusInternalServerError, gin.H{"code": 9006})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{
//		"msg": 200,
//	})
//}

func InsertGoods(c *gin.Context) {
	var report structs.Goods
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	if claim.Permissions < 1 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}
	//接受参数
	err = c.ShouldBindJSON(&report)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		return
	}
	fmt.Printf("report: %+v\n", report)
	// 使用Validate验证
	validate := validator.New()
	err = validate.Struct(report)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		return
	}
	//数据校验通过，开始存入数据库
	err = dao.PutGoods(&report)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9006})
		return
	}
	c.JSON(200, gin.H{"code": 200})
}

func GetAdminGoods(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions <= 0 {
		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
		return
	}
	goods, err := dao.GetGoods()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
	}
	c.JSON(http.StatusOK, goods)
}

func GetAllReports(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions <= 1 {
		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
		return
	}
	reports, err := dao.GetReport()
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":    200,
		"reports": reports,
	})
}

func PassReport(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	fmt.Printf("权限： %v, 类型：%T\n", claim.Permissions, claim.Permissions)
	if claim.Permissions != int8(2) {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}

	var report structs.Report
	//接受参数
	id := c.Query("id")
	state := c.Query("state")
	if id == "" {
		c.JSON(http.StatusNotFound, gin.H{"code": 9000})
		return
	}

	i, _ := strconv.ParseInt(state, 10, 8)
	report.Id, _ = strconv.Atoi(id)
	report.ReportStatus = int8(i)
	report.Receiver = claim.Username
	report.ReportTime = time.Now()

	err = dao.UpdateReportPass(report)
	c.JSON(http.StatusOK, gin.H{
		"msg": 200,
	})
}

func LookReport(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	fmt.Printf("权限： %v, 类型：%T\n", claim.Permissions, claim.Permissions)
	if claim.Permissions < 1 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}

	var report structs.Report
	//接受参数
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusNotFound, gin.H{"code": 9000})
		return
	}

	report.Id, _ = strconv.Atoi(id)
	report.ReportStatus = 4
	report.Reviewer = claim.Username
	report.ReceiverTime = time.Now()

	err = dao.UpdateReportLook(report)
	c.JSON(http.StatusOK, gin.H{
		"msg": 200,
	})
}

func ReportEnd(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	fmt.Printf("权限： %v, 类型：%T\n", claim.Permissions, claim.Permissions)
	if claim.Permissions != int8(2) {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}

	var report structs.Report
	//接受参数
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusNotFound, gin.H{"code": 9000})
		return
	}
	state, err := strconv.ParseInt(c.Query("state"), 10, 8)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		return
	}

	report.Id, _ = strconv.Atoi(id)
	report.ReportStatus = int8(state)

	err = dao.UpdateReportStatus(report, claim.Username)
	c.JSON(http.StatusOK, gin.H{
		"msg": 200,
	})
}

func UploadFile(c *gin.Context) {
	var urls []string
	form, _ := c.MultipartForm()
	files := form.File["file"]
	fileType := c.PostForm("fileType")
	for i, f := range files {
		log.Println(f.Filename) //print filename
		switch fileType {
		case "report":
			fileType = "src/reports/"
		case "avatar":
			fileType = "src/avatar/"
		case "house":
			fileType = "src/house/"
		case "slideshow":
			fileType = "src/slideshow/"
		}
		dst := fmt.Sprintf("./%s%s", fileType, f.Filename) //构建目标文件的位置
		urls = append(urls[0:i], "https://"+c.Request.Host+"/"+fileType+f.Filename)
		fmt.Println("file:", dst)
		//save the file to specific dst
		err := c.SaveUploadedFile(f, dst)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"code": 9006})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"uploading": "done", "message": "success", "urls": urls})
}

func Report(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	if claim.Permissions <= 0 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}
	var report structs.Report
	err = c.ShouldBindJSON(&report)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9006})
		return
	}
	// 使用Validate验证
	validate := validator.New()
	err = validate.Struct(report)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 9001})
		return
	}
	//验证通过
	report.Originator = claim.Username
	report.ReportTime = time.Now()
	report.ReportStatus = 1
	err = dao.PutReport(report)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9006})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
	})
}

//AddCustomer 新增客户
func AddCustomer(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9007})
		return
	}
	if claim.Permissions < 1 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}
	var customer structs.Customer
	err = c.ShouldBindJSON(&customer)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		return
	}
	// 使用Validate验证
	validate := validator.New()
	err = validate.Struct(customer)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9001})
		return
	}
	err = dao.AddCustomer(customer)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"code": 9006})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 200,
	})
}

func UpdateMaster(c *gin.Context) {
	strToken := c.Param("token")
	userPhone := c.Query("phone")
	power := c.Query("tag")
	//验证token
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions == 2 {
		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
		return
	}
	tag, err := strconv.Atoi(power)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	err = dao.CreateMaster(userPhone, claim.Username, int8(tag))
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"msg": 200,
	})
}

func AddMaster(c *gin.Context) {
	strToken := c.Param("token")
	list := c.Query("list")
	//验证token
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions < 2 {
		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
		return
	}

	//从注册信息表获取当前用户信息
	master, err := dao.QuerrySignUpMaster(list)
	master.Power = int8(2) //赋予权限

	err = dao.AddMaster(master)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"msg": 200,
	})
}

//func AddAdmin(c *gin.Context) {
//	strToken := c.Param("token")
//	claim, err := verifyAction(strToken)
//	if err != nil {
//		c.String(http.StatusNotFound, err.Error())
//		return
//	}
//	if claim.Permissions == 2 {
//		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
//		return
//	}
//}

//GetALLSignUpMasters 获取所有申请注册的用户信息
//func GetALLSignUpMasters(c *gin.Context) {
//	strToken := c.Param("token")
//	AdminVerify := c.Query("verify")
//	claim, err := verifyAction(strToken)
//	if err != nil {
//		c.String(http.StatusNotFound, err.Error())
//		return
//	}
//	if claim.Permissions == 2 {
//		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
//		return
//	}
//}

//GetAllMaster 获取所有用户
func GetAllMaster(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions == 2 {
		c.JSON(http.StatusNotFound, gin.H{"msg": "无权操作"})
		return
	}
	master, err := dao.GetAllMaster()
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"msg":  master,
		"code": 200,
	})
}

func GetALlCostomer(c *gin.Context) {
	strToken := c.Param("token")
	claim, err := verifyAction(strToken)
	if err != nil {
		c.String(http.StatusNotFound, err.Error())
		return
	}
	if claim.Permissions < 1 {
		c.JSON(http.StatusNotFound, gin.H{"code": 9008})
		return
	}
	customers, err := dao.GetAllCustomer()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 9004})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":      200,
		"customers": customers,
	})
}
