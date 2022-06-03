package structs

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Goods struct {
	Id        int64     `json:"id"`
	GoodsType string    `validate:"lte=3,required" json:"goodsType" db:"goodsType"`
	Name      string    `validate:"lte=20,required" json:"name" db:"name"`
	Tags      []string  `validate:"required" json:"tags" db:"tags"`
	Price     string    `validate:"lte=10,required" json:"price" db:"price"`
	StartTime string    `validate:"lte=11,required" json:"startTime" db:"startTime"`
	Pictures  []string  `validate:"gte=1,required" json:"pictures" db:"pictures"`
	HouseType HouseType `validate:"required" json:"houseType" db:"houseType"`
	Address   Address   `validate:"required" json:"address" db:"address"`
}

type HouseType []struct {
	Name         string `validate:"lte=20,required" json:"name" db:"name"`
	Size         string `validate:"lte=6,required" json:"size" db:"size"`
	Picture      string `validate:"required" json:"picture" db:"picture"`
	State        bool   `validate:"required,oneof=ture false" json:"state" db:"state"`
	DecorateType string `validate:"lte=4" json:"decorateType" db:"decorateType"`
	Price        string `validate:"required lte=6" json:"price" db:"price"`
}

type Address struct {
	Detail string  `validate:"lte=60,required" json:"detail" db:"detail"`
	Lon    float64 `validate:"lte=180,gte=0,required" json:"lon" db:"lon"`
	Lat    float64 `validate:"lte=180,gte=0,required" json:"lat" db:"lat"`
}

type Report struct {
	Id           int       `json:"id" db:"id"`
	Building     string    `validate:"required" json:"building" db:"building"` //楼盘
	Customer     Customer  //客户
	ReportTime   time.Time `json:"reportTime" db:"reportTime"`     //报备时间
	Originator   string    `json:"originator" db:"originator"`     //报备发起人
	Reviewer     string    `json:"reviewer" db:"reviewer"`         //带看人
	ReviewerTime time.Time `json:"reviewerTime" db:"reviewerTime"` //带看时间
	Receiver     string    `json:"receiver" db:"receiver"`         //审核人
	ReceiverTime time.Time `json:"receiverTime" db:"receiverTime"` //审核时间
	ReportStatus int8      `json:"reportStatus" db:"reportStatus"` //状态
}

type AdminUser struct {
	Phone string `json:"phone" db:"phone"`
	Power int8   `json:"power" db:"power"`
	Code  string `json:"code" db:"code"`
}

type User struct {
	Name     string `json:"name" db:"name"`
	Phone    string `json:"phone" db:"phone"`
	Openid   string `json:"openid" db:"openid"`
	Avatar   string `json:"avatar" db:"avatar"`
	Password string `json:"password" db:"password"`
}

type SignUp struct {
	Phone    string `validate:"len=11" json:"phone"`
	Code     string `validate:"required" json:"code" db:"code"`
	SMScode  string `validate:"len=6" json:"SMScode"`
	Password string `validate:"required" json:"password"`
}

type MobileStrut struct {
	Code          string `form:"code" binding:"required"`
	Iv            string `form:"iv" binding:"required"`
	EncryptedData string `form:"encryptedData" binding:"required"`
}

type VerifyStruct struct {
	Phone string `json:"phone"`
	Psw   string `json:"psw"`
	Code  string `json:"code"`
}

type JWTClaims struct { // token里面添加用户信息，验证token后可能会用到用户信息
	jwt.StandardClaims
	Userphone   string `json:"userphone"`
	Username    string `json:"username"`
	Permissions int8   `json:"permissions"`
}

type Customer struct {
	CustomerName   string `validate:"required" json:"customerName" db:"customerName"`   //客户姓名
	CustomerPhone  string `validate:"required" json:"customerPhone" db:"customerPhone"` //客户电话
	CustomerGender int8   `json:"customerGender" db:"customerGender"`                   //客户性别
	Remarks        string `json:"remarks" db:"remarks"`                                 //备注
}

type WXLoginResp struct {
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

//Master 员工结构体
type Master struct {
	Id       string `json:"id"`
	Phone    string `validate:"len=11" json:"phone"`
	Name     string `validate:"max=11" json:"name"`
	Power    int8   `json:"power"` //员工权限
	Avatar   string `json:"avatar"`
	Tag      string `json:"tag"`                              //个人标签
	Markers  string `json:"markers"`                          //备注
	Other    string `validate:"required,max=40" json:"other"` //其他信息
	Verify   int64  `json:"verify"`                           //员工登录态
	Psw      string `validate:"required,max=16,min=9" json:"psw"`
	SMSCode  string `validate:"len=6" json:"SMSCode"` //注册时使用的验证码
	SignTime string `json:"signTime"`                 //注册时间
}
