package server

import (
	"encoding/base32"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

type Message struct {
	Name string
	Msg  string
}

// 处理DNS查询的回调函数
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, messageChan chan Message, caches map[string]string, baseDomain string) {
	go func() {
		// 获取请求的查询内容
		query := r.Question[0].Name // data.finishflag.clientname.baseDomain.
		if !strings.Contains(query, baseDomain) {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}
		str := strings.ReplaceAll(query, "."+baseDomain+".", "") //data.finishflag.clientname
		index := strings.LastIndex(str, ".")
		if index == -1 {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}

		clientName := str[index+1:]
		str = str[:index] //data.finishflag
		index = strings.LastIndex(str, ".")
		if index == -1 {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}

		data := strings.ReplaceAll(str[:index], ".", "")
		caches[clientName] = caches[clientName] + data
		if str[index+1:] == "1" {
			base32Enc := caches[clientName]

			padCount := (8 - len(base32Enc)%8) % 8
			padString := strings.Repeat("=", padCount)
			base32Enc = base32Enc + padString

			msg, err := base32.StdEncoding.DecodeString(base32Enc)
			caches[clientName] = ""
			if err != nil {
				replyDNSTXT(w, r, query, "invalid format")
				return
			}
			messageChan <- Message{
				Name: clientName,
				Msg:  string(msg),
			}
		}
		replyDNSTXT(w, r, query, "ok")
	}()
}
func replyDNSTXT(w dns.ResponseWriter, r *dns.Msg, query string, msg string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	txtRecord := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   query,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: []string{msg}, // 返回 "ok" 表示成功
	}
	m.Answer = append(m.Answer, txtRecord)
	w.WriteMsg(m)
}
func ListenAndServer(baseDomain string) chan Message {
	// 创建DNS服务器
	server := &dns.Server{
		Addr: ":53", // 监听 53 端口
		Net:  "udp", // 使用 UDP 协议
	}
	msgChan := make(chan Message, 1024)
	caches := make(map[string]string)
	// 注册 DNS 查询处理器
	dns.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		handleDNSRequest(w, m, msgChan, caches, baseDomain)
	})

	// 启动服务器并开始监听
	go func() {
		fmt.Println("DNS tunnel server started on port 53")
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()
	return msgChan
}
