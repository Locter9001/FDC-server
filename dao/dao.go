package dao

import (
	"FDC-WeOne/structs"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Unknwon/goconfig"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"log"
	"time"
)

// db 定义一个全局对象db
var db *sqlx.DB

// InitDB 定义一个初始化数据库的函数
func InitDB() (err error) {
	cfg, err := goconfig.LoadConfigFile("config/conf.ini")
	if err != nil {
		log.Panicf("无法打开配置文件, 详细: %s", err)
	}
	mysql, err := cfg.GetSection("mysql")
	if err != nil {
		log.Panicf("无法读取配置文件信息， 详细： %s", err)
	}
	name := mysql["username"]
	psw := mysql["password"]
	url := mysql["url"]
	dsn := name + ":" + psw + url + "?charset=utf8&parseTime=True"
	// 也可以使用MustConnect连接不成功就panic
	db, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		log.Printf("链接数据库失败, 详细: %v\n", err)
		return
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	return err
}

func PutGoods(Goods *structs.Goods) error {
	fmt.Printf("传入参数： %v\n", Goods)
	tags, err := json.Marshal(Goods.Tags)
	pictures, err := json.Marshal(Goods.Pictures)
	houseType, err := json.Marshal(Goods.HouseType)
	address, err := json.Marshal(Goods.Address)
	if err != nil {
		return err
	}
	sqlStr := `insert into goods (goodsType, name, tags, price, startTime, pictures, houseType, address) value(?,?,?,?,?,?,?,?)`
	res, err := db.Exec(sqlStr, Goods.GoodsType, Goods.Name, tags, Goods.Price, Goods.StartTime, pictures, houseType, address)
	if err != nil {
		return err
	}
	fmt.Println(res)
	return err
}

func GetGoods() ([]structs.Goods, error) {
	var (
		Goods []structs.Goods
		idx   int
	)
	sqlStr := `select * from goods`
	rows, err := db.Query(sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
next:
	for rows.Next() {
		var (
			data      structs.Goods
			tags      []byte
			pictures  []byte
			houseType []byte
			address   []byte
		)
		err := rows.Scan(&data.Id, &data.GoodsType, &data.Name, &tags, &data.Price, &data.StartTime, &pictures, &houseType, &address)
		if err != nil {
			fmt.Println(err)
			continue next
		}
		err = json.Unmarshal(tags, &data.Tags)
		err = json.Unmarshal(pictures, &data.Pictures)
		err = json.Unmarshal(houseType, &data.HouseType)
		err = json.Unmarshal(address, &data.Address)
		if err != nil {
			fmt.Println(err)
			continue next
		}
		Goods = append(Goods[0:idx], data)
		idx++
	}
	return Goods, err
}

func PutReport(report structs.Report) error {
	sqlStr := `insert into reports(customerName, building, customerPhone, customerGender, reportTime, remarks, originator, reviewer, reviewerTime, receiver, receiverTime, reportStatus) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
	exec, err := db.Exec(sqlStr, report.Customer.CustomerName, report.Building, report.Customer.CustomerPhone, report.Customer.CustomerGender, report.ReportTime, report.Customer.Remarks, report.Originator, "0", time.Now(), "0", time.Now(), report.ReportStatus)
	if err != nil {
		return err
	}
	num, err := exec.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Printf("更新报备： 报备表已更新 %v 行, 来自：%s 的操作", num, report.Originator)
	return nil
}

func UpdateReportPass(report structs.Report) error {
	sqlStr := `update reports set receiver = ?, receiverTime = ?, reportStatus = ? where id = ?`
	row, err := db.Exec(sqlStr, report.Receiver, report.ReceiverTime, report.ReportStatus, report.Id)
	if err != nil {
		fmt.Println(err)
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Printf("更新报备： 报备表已更新 %v 行, 来自：%s 的操作", num, report.Receiver)
	return nil
}

func UpdateReportLook(report structs.Report) error {
	sqlStr := `update reports set reviewer = ?, reviewerTime = ?, reportStatus = ? where id = ?`
	row, err := db.Exec(sqlStr, report.Reviewer, report.ReviewerTime, report.ReportStatus, report.Id)
	if err != nil {
		fmt.Println(err)
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Printf("更新报备： 报备表已更新 %v 行, 来自：%s 的操作", num, report.Reviewer)
	return nil
}

func UpdateReportStatus(report structs.Report, boss string) error {
	sqlStr := `update reports set reportStatus = ? where id = ?`
	row, err := db.Exec(sqlStr, report.ReportStatus, report.Id)
	if err != nil {
		fmt.Println(err)
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Printf("更新报备： 报备表已更新 %v 行, 来自：%s 的操作", num, boss)
	return nil
}

//GetReport 获取所有报备
func GetReport() ([]structs.Report, error) {
	sqlStr := `select * from reports`
	rows, err := db.Query(sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []structs.Report
	num := 0
thefor:
	for rows.Next() {
		var report structs.Report
		err := rows.Scan(&report.Id, &report.Customer.CustomerName, &report.Building, &report.Customer.CustomerPhone, &report.Customer.CustomerGender, &report.ReportTime, &report.Customer.Remarks, &report.Originator, &report.Reviewer, &report.ReviewerTime, &report.Receiver, &report.ReceiverTime, &report.ReportStatus)
		if err != nil {
			fmt.Println(err)
			goto thefor
		}
		reports = append(reports[0:num], report)
		num++
	}
	return reports, nil
}

//CreateMaster 创建管理员
func CreateMaster(phone, adminPhone string, power int8) error {
	sqlStr := `update admin set power = ? where phone = ?`
	row, err := db.Exec(sqlStr, power, phone)
	if err != nil {
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Printf("新增master用户： admin表已更新 %v 行， 来自：%s 的操作", num, adminPhone)
	return nil
}

//AddMaster 新增员工
func AddMaster(master structs.Master) error {
	sqlStr := `insert into admin (phone, name, power, avatar, verify, psw, signTime) values (?,?,?,?,?,?,?)`
	rows, err := db.Exec(sqlStr, master.Phone, master.Name, master.Power, master.Avatar, 0, master.Power, master.SignTime)
	if err != nil {
		return err
	}
	num, err := rows.RowsAffected()
	if err != nil {
		return err
	}
	if num == 0 {
		return errors.New("更新0行")
	}
	return nil
}

//QuerrySignUpMaster 获取注册表的用户信息
func QuerrySignUpMaster(phone string) (structs.Master, error) {
	master := structs.Master{}
	sqlStr := `select phone, name, avatar, other, psw, signTime from signup_master where phone = ?`
	err := db.QueryRow(sqlStr, phone).Scan(&master.Phone, &master.Name, &master.Avatar, &master.Other, &master.Psw, &master.SignTime)
	if err != nil {
		return structs.Master{}, err
	}
	return master, nil
}

//GetAllMasterSignUpList 获取注册表的用户信息
func GetAllMasterSignUpList(power int) ([]structs.Master, error) {
	var masters []structs.Master
	sqlStr := `select phone, name, avatar, other, psw, signTime from signup_master`
	rows, err := db.Query(sqlStr)
	if err != nil {
		return []structs.Master{}, err
	}
	num := 0
rows:
	for rows.Next() {
		master := structs.Master{}
		err2 := rows.Scan(&master.Phone, &master.Name, &master.Avatar, &master.Other, &master.Psw, &master.SignTime)
		if err2 != nil {
			continue rows
		}
		if power < 1 {
			master.Psw = "无权查看"
		}
		masters = append(masters[0:num], master)
	}
	return masters, nil
}

//QuerryUser 查询用户，手机号查询，返回用户信息
func QuerryUser(str string) (theUser structs.User, Permissions int8, err error) {
	var sqlStr string
	if len(str) == 11 {
		sqlStr = `select * from users where phone = ?`
	} else {
		sqlStr = `select * from users where openid = ?`
	}
	//搜索用户
	var user structs.User
	err = db.QueryRow(sqlStr, str).Scan(&user.Name, &user.Phone, &user.Openid, &user.Avatar)
	if err != nil {
		log.Println(err)
		return user, 0, err
	}
	//获取用户权限
	PsqlStr := `select power from admin where phone = ?`
	err2 := db.QueryRow(PsqlStr, user.Phone).Scan(&Permissions)
	if err2 != nil {
		Permissions = 0 //无权用户，返回0
	}

	return user, Permissions, err
}

//AddCustomer 保存新增的客户
func AddCustomer(data structs.Customer) error {
	sqlStr := `insert into customers(customerName, customerPhone, customerGender, remarks) values (?,?,?,?)`
	row, err := db.Exec(sqlStr, data.CustomerName, data.CustomerPhone, data.CustomerGender, data.Remarks)
	if err != nil {
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Printf("新增客户： 客户表已更新 %v 行", num)
	return nil
}

//VerifyLogin 检验登录
func VerifyLogin(phone string) (theUser string, err error) {
	var psw string
	sqlStr := `select psw from verify_all where phone = ?`
	err = db.QueryRow(sqlStr, phone).Scan(&psw)
	if err != nil {
		return psw, err
	}
	return psw, err
}

//QuerryMaster 查询员工
func QuerryMaster(phone string) (structs.Master, error) {
	master := structs.Master{}
	sqlStr := `select id, phone, ifnull(name, '默认用户名'), power, ifnull(avatar, '默认头像'), ifnull(tag, '默认标签'), ifnull(markers, '备注'), ifnull(other, '默认'), verify from admin where phone = ?`
	err := db.QueryRow(sqlStr, phone).Scan(&master.Id, &master.Phone, &master.Name, &master.Power, &master.Avatar, &master.Tag, &master.Markers, &master.Other, &master.Verify)
	if err != nil {
		return structs.Master{}, err
	}
	return master, err
}

//VerifyMaster 查询用户是否注册
func VerifyMaster(phone string) error {
	var id int
	sqlStr := `select 1 from admin where phone = ? limit 1`
	err := db.QueryRow(sqlStr, phone).Scan(&id)
	if err != nil {
		return nil
	}
	return errors.New("数据已存在")
}

//PutAdminVerify 保存员工生成的登录态
func PutAdminVerify(verify int64, phone string) error {
	sqlStr := `update admin set verify=? where phone = ?`
	row, err := db.Exec(sqlStr, verify, phone)
	if err != nil {
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Println(verify, phone, num)
	if num == 0 {
		return errors.New("更新0行")
	}
	return nil
}

//PutMasterSignUpInfo 保存注册员工的信息至暂存表
func PutMasterSignUpInfo(master structs.Master) error {
	sqlStr := `insert into signup_master (phone, name, avatar, other, psw, signTime) values (?,?,?,?,?,?) `
	row, err := db.Exec(sqlStr, master.Phone, master.Name, master.Avatar, master.Other, master.Psw, master.SignTime)
	if err != nil {
		return err
	}
	num, err := row.RowsAffected()
	if err != nil {
		return err
	}
	if num == 0 {
		return errors.New("更新0行")
	}
	return nil
}

func PutVCode(phone, vcode string) {
	sqlStr := `insert into vcodes (phone, vcode) value(?,?)`
	_, err := db.Exec(sqlStr, phone, vcode)
	if err != nil {
		log.Println(err)
	}
}

func GetVCode(phone string) (string, error) {
	var code string
	sqlStr := `select vcode from vcodes where phone = ?`
	err := db.QueryRow(sqlStr, phone).Scan(&code)
	if err != nil {
		log.Println(err)
		return code, err
	}
	return code, err
}

func PutVerifyInfo(phone, psw string) error {
	sqlStr := `insert into verify_all (phone, psw) values (?,?)`
	_, err := db.Exec(sqlStr, phone, psw)
	if err != nil {
		return err
	}
	return nil
}

func PutUserInfo(user *structs.User) error {
	_, err := VerifyLogin(user.Phone)
	if err == nil {
		sqlStr := `delete from verify_all where phone = ?`
		_, err := db.Exec(sqlStr, user.Phone)
		if err != nil {
			return err
		}
	}
	err = PutVerifyInfo(user.Phone, user.Password)
	if err != nil {
		return err
	}
	sqlStr := `insert into users (name, phone, openid, avatar) value (?,?,?,?)`
	_, err = db.Exec(sqlStr, user.Name, user.Phone, user.Openid, user.Avatar)
	if err != nil {
		return err
	}
	return nil
}

func GetAllMaster() (map[string]string, error) {
	sqlStr := `select phone,power from admin`
	rows, err := db.Query(sqlStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	master := make(map[string]string)
masters:
	for rows.Next() {
		var phone string
		var tag string
		err := rows.Scan(&phone, &tag)
		if err != nil {
			goto masters
		}
		master[phone] = tag
	}
	return master, err
}

func GetAllCustomer() ([]structs.Customer, error) {
	var customers []structs.Customer
	sqlStr := `select * from customers`
	rows, err := db.Query(sqlStr)
	if err != nil {
		return nil, err
	}
	num := 0
cus:
	for rows.Next() {
		var customer structs.Customer
		err := rows.Scan(&customer.CustomerName, &customer.CustomerPhone, &customer.CustomerGender, &customer.Remarks)
		if err != nil {
			goto cus
		}
		customers = append(customers[0:num], customer)
		num++
	}
	return customers, nil
}
