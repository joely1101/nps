package controllers

import (
	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/rate"
	"ehang.io/nps/server"
	"github.com/astaxie/beego"
	"ehang.io/nps/server/tool"
	"github.com/astaxie/beego/logs"
	"fmt"
)

type DeviceController struct {
	BaseController
}
func (s *DeviceController) Dashboard() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	s.Data["data"] = server.GetDashboardData()
	clientIdSession := s.GetSession("clientId")
    if clientIdSession == nil {
		s.Data["vkey"] = "your_register_key"
	}else if c, err := file.GetDb().GetClient(clientIdSession.(int)); err == nil {
		s.Data["vkey"] = c.VerifyKey
	}else{
		s.Data["vkey"] = "your_register_key"
	}
	s.SetInfo("dashboard")
	s.display("device/dashboard")
}

func (s *DeviceController) List() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "device"
		s.SetInfo("device")
		s.display("device/list")
		return
	}
	start, length := s.GetAjaxParams()
	clientIdSession := s.GetSession("clientId")
	var clientId int
	if clientIdSession == nil {
		clientId = 0
	} else {
		clientId = clientIdSession.(int)
	}
	list, cnt := server.GetClientList(start, length, s.getEscapeString("search"), s.getEscapeString("sort"), s.getEscapeString("order"), clientId)
	cmd := make(map[string]interface{})
	ip := s.Ctx.Request.Host
	cmd["ip"] = common.GetIpByAddr(ip)
	cmd["bridgeType"] = beego.AppConfig.String("bridge_type")
	cmd["bridgePort"] = server.Bridge.TunnelPort
	s.AjaxTable(list, cnt, cnt, cmd)
}
//添加客户端
func (s *DeviceController) Addclient() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "device"
		s.SetInfo("add client")
		s.display("device/addclient")
		//s.display()
	} else {
		t := &file.Client{
			VerifyKey: s.getEscapeString("vkey"),
			Id:        int(file.GetDb().JsonDb.GetClientId()),
			Status:    true,
			Remark:    s.getEscapeString("remark"),
			Cnf: &file.Config{
				U:        s.getEscapeString("u"),
				P:        s.getEscapeString("p"),
				Compress: common.GetBoolByStr(s.getEscapeString("compress")),
				Crypt:    s.GetBoolNoErr("crypt"),
			},
			ConfigConnAllow: s.GetBoolNoErr("config_conn_allow"),
			RateLimit:       s.GetIntNoErr("rate_limit"),
			MaxConn:         s.GetIntNoErr("max_conn"),
			WebUserName:     s.getEscapeString("web_username"),
			WebPassword:     s.getEscapeString("web_password"),
			MaxTunnelNum:    s.GetIntNoErr("max_tunnel"),
			Flow: &file.Flow{
				ExportFlow: 0,
				InletFlow:  0,
				FlowLimit:  int64(s.GetIntNoErr("flow_limit")),
			},
		}
		if err := file.GetDb().NewClient(t); err != nil {
			s.AjaxErr(err.Error())
		}
		s.AjaxOk("add client success")
	}
}

func (s *DeviceController) GetClient() {
	if s.Ctx.Request.Method == "POST" {
		id := s.GetIntNoErr("id")
		data := make(map[string]interface{})
		if c, err := file.GetDb().GetClient(id); err != nil {
			data["code"] = 0
		} else {
			data["code"] = 1
			data["data"] = c
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

//修改客户端
func (s *DeviceController) Editclient() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "device"
		if c, err := file.GetDb().GetClient(id); err != nil {
			s.error()
		} else {
			s.Data["c"] = c
		}
		s.SetInfo("edit client")
		ip := s.Ctx.Request.Host
		s.Data["ip"] = common.GetIpByAddr(ip)
		s.Data["bridgeType"] = beego.AppConfig.String("bridge_type")
		s.Data["bridgePort"] = server.Bridge.TunnelPort

		s.display("device/editclient")
		//s.display()
	} else {
		if c, err := file.GetDb().GetClient(id); err != nil {
			s.error()
		} else {
			if s.getEscapeString("web_username") != "" {
				if s.getEscapeString("web_username") == beego.AppConfig.String("web_username") || !file.GetDb().VerifyUserName(s.getEscapeString("web_username"), c.Id) {
					s.AjaxErr("web login username duplicate, please reset")
					return
				}
			}
			if s.GetSession("isAdmin").(bool) {
				if !file.GetDb().VerifyVkey(s.getEscapeString("vkey"), c.Id) {
					s.AjaxErr("Vkey duplicate, please reset")
					return
				}
				c.VerifyKey = s.getEscapeString("vkey")
				c.Flow.FlowLimit = int64(s.GetIntNoErr("flow_limit"))
				c.RateLimit = s.GetIntNoErr("rate_limit")
				c.MaxConn = s.GetIntNoErr("max_conn")
				c.MaxTunnelNum = s.GetIntNoErr("max_tunnel")
			}
			c.Remark = s.getEscapeString("remark")
			c.Cnf.U = s.getEscapeString("u")
			c.Cnf.P = s.getEscapeString("p")
			c.Cnf.Compress = common.GetBoolByStr(s.getEscapeString("compress"))
			c.Cnf.Crypt = s.GetBoolNoErr("crypt")
			b, err := beego.AppConfig.Bool("allow_user_change_username")
			if s.GetSession("isAdmin").(bool) || (err == nil && b) {
				c.WebUserName = s.getEscapeString("web_username")
			}
			c.WebPassword = s.getEscapeString("web_password")
			c.ConfigConnAllow = s.GetBoolNoErr("config_conn_allow")
			if c.Rate != nil {
				c.Rate.Stop()
			}
			if c.RateLimit > 0 {
				c.Rate = rate.NewRate(int64(c.RateLimit * 1024))
				c.Rate.Start()
			} else {
				c.Rate = rate.NewRate(int64(2 << 23))
				c.Rate.Start()
			}
			file.GetDb().JsonDb.StoreClientsToJsonFile()
		}
		s.AjaxOk("save success")
	}
}

//更改状态
func (s *DeviceController) ChangeClientStatus() {
	id := s.GetIntNoErr("id")
	if client, err := file.GetDb().GetClient(id); err == nil {
		client.Status = s.GetBoolNoErr("status")
		if client.Status == false {
			server.DelClientConnect(client.Id)
		}
		s.AjaxOk("modified success")
	}
	s.AjaxErr("modified fail")
}

//删除客户端
func (s *DeviceController) Delclient() {
	id := s.GetIntNoErr("id")
	if err := file.GetDb().DelClient(id); err != nil {
		s.AjaxErr("delete error")
	}
	server.DelTunnelAndHostByClientId(id, false)
	server.DelClientConnect(id)
	s.AjaxOk("delete success")
}
//tunnel/rule 
func (s *DeviceController) Addrule() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["type"] = s.getEscapeString("type")
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["macaddress"] = s.getEscapeString("macaddress")
		s.Data["target_ipport"] = s.getEscapeString("target_ipport")
		s.Data["rulename"] = s.getEscapeString("name")
		vp:=beego.AppConfig.String("allow_ports") 
		if vp ==""{
			vp="40000-60000"
		}
		s.Data["ValidPort"] = vp
		s.SetInfo("addx tunnel")
		s.display("device/addrule")
	} else {
		t := &file.Tunnel{
			Port:      s.GetIntNoErr("port"),
			ServerIp:  s.getEscapeString("server_ip"),
			Mode:      s.getEscapeString("type"),
			Target:    &file.Target{TargetStr: s.getEscapeString("target"),TargetMacStr:s.getEscapeString("macaddr"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			Id:        int(file.GetDb().JsonDb.GetTaskId()),
			Status:    true,
			Remark:    s.getEscapeString("remark"),
			Password:  s.getEscapeString("password"),
			LocalPath: s.getEscapeString("local_path"),
			StripPre:  s.getEscapeString("strip_pre"),
			Flow:      &file.Flow{},
		}
		NoSameTarget:= s.GetIntNoErr("NoSameTarget")
		if t.Remark == "" {
			s.AjaxErr("The name can not be empty!")
		}
		if t.Port == 0{
			//try to choose valid port.
			t.Port = file.GetDb().GetTcpvalidport()
			if t.Port == 0{
				s.AjaxErr("Auto Port selection fail!")
			}
		}
		if NoSameTarget != 0{
			c:=file.GetDb().GetTaskByTarget(s.getEscapeString("target"))
			if c != nil{
				//just retunr the port
				if !t.RunStatus {
					//t.Status = true
					server.StartTask(c.Id)
				}
				msg := fmt.Sprintf("success!!Port=%d",c.Port)
				s.AjaxOk(msg)
				return
			}
		}
		if !tool.TestServerPort(t.Port, t.Mode) {
			s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
		}
		var err error
		if t.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr(err.Error())
		}
		if t.Client.MaxTunnelNum != 0 && t.Client.GetTunnelNum() >= t.Client.MaxTunnelNum {
			s.AjaxErr("The number of tunnels exceeds the limit")
		}
		if err := file.GetDb().NewTask(t); err != nil {
			s.AjaxErr(err.Error())
		}
		if err := server.AddTask(t); err != nil {
			s.AjaxErr(err.Error())
		} else {
			if NoSameTarget !=0 {
				msg := fmt.Sprintf("success!!Port=%d",t.Port)
				s.AjaxOk(msg)
			}
			s.AjaxOk("add success")
		}
	}
}

func (s *DeviceController) Editrule() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			s.Data["t"] = t
		}
		vp:=beego.AppConfig.String("allow_ports") 
		if vp ==""{
			vp="40000-60000"
		}
		s.Data["ValidPort"] = vp
		s.SetInfo("edit tunnel")
		s.display("device/editrule")
	} else {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
				return
			} else {
				t.Client = client
			}
			if s.GetIntNoErr("port") != t.Port {
				if !tool.TestServerPort(s.GetIntNoErr("port"), t.Mode) {
					s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
					return
				}
				t.Port = s.GetIntNoErr("port")
			}
			t.ServerIp = s.getEscapeString("server_ip")
			t.Mode = s.getEscapeString("type")
			t.Target = &file.Target{TargetStr: s.getEscapeString("target"),TargetMacStr: s.getEscapeString("macaddr")}
			t.Password = s.getEscapeString("password")
			t.Id = id
			t.LocalPath = s.getEscapeString("local_path")
			t.StripPre = s.getEscapeString("strip_pre")
			t.Remark = s.getEscapeString("remark")
			t.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			logs.Warn("t.Target to %s", t.Target.TargetMacStr)
			file.GetDb().UpdateTask(t)
			server.StopServer(t.Id)
			server.StartTask(t.Id)
		}
		s.AjaxOk("modified success")
	}
}


func (s *DeviceController) Delrule() {
	id := s.GetIntNoErr("id")
	if err := server.DelTask(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}
 
func (s *DeviceController) Startrule() {
	id := s.GetIntNoErr("id")
	if err := server.StartTask(id); err != nil {
		s.AjaxErr("start error")
	}
	s.AjaxOk("start success")
}
 
func (s *DeviceController) Sendwol() {
	cid := s.GetIntNoErr("cid")
	mac := s.getEscapeString("macaddr")
	if mac=="" {
		s.AjaxErr("Invalid mac address")
		return
	}
	if  ok := server.Bridge.SendCmd2Client(cid,"wol:"+mac); ok != nil {
		s.AjaxErr("Send Magic packet fail")
		return
	} 
	s.AjaxOk("Send Magic packet success!!")
}

func (s *DeviceController) Stoprule() {
	id := s.GetIntNoErr("id")
	if err := server.StopServer(id); err != nil {
		s.AjaxErr("stop error")
	}
	s.AjaxOk("stop success")
}
func (s *DeviceController) GetTunnel() {
	start, length := s.GetAjaxParams()
	taskType := s.getEscapeString("type")
	clientId := s.GetIntNoErr("client_id")
	list, cnt := server.GetTunnel(start, length, taskType, clientId, s.getEscapeString("search"))
	s.AjaxTable(list, cnt, cnt, nil)
}
func (s *DeviceController) ArpList() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "arplist"
		s.SetInfo("Show Arp List")
		//s.display("device/addclient")
		s.display()
	}
}

func (s *DeviceController) GetArpList() {
	var ae []*file.ARPEntry
	clientId := s.GetIntNoErr("client_id")
	//Handling Ported Access
	file.GetDb().JsonDb.ARPEntries.Range(func(key, value interface{}) bool {
		v := value.(*file.ARPEntry)
		if v.Client_id == clientId{
			ae = append(ae, v)
		}
		
		return true
	})
	s.AjaxTable(ae, len(ae), len(ae), nil)
}
func (s *DeviceController) DelArpEntry() {
	macaddr := s.getEscapeString("mac_addr")
	file.GetDb().JsonDb.ARPEntries.Delete(macaddr)
	s.AjaxOk("Delete success")
}