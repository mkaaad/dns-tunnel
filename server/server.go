package server

import (
	"encoding/base32"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var msgChan = make(chan string, 1024)
var caches sync.Map

// 处理DNS查询的回调函数
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, baseDomain string) {
	go func() {
		// 获取请求的查询内容
		query := r.Question[0].Name // data.finishflag.messageID.baseDomain.
		index := strings.LastIndex(query, baseDomain)
		if index <= 0 {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}
		str := query[:index-1] //data.finishflag.messageID
		index = strings.LastIndex(str, ".")
		if index == -1 {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}

		messageID := str[index+1:]
		str = str[:index] //data.finishflag
		index = strings.LastIndex(str, ".")
		if index == -1 {
			if str == "2" {
				if _, ok := caches.LoadOrStore(messageID, ""); ok {
					replyDNSTXT(w, r, query, "exists")
					return
				} else {
					replyDNSTXT(w, r, query, "ok")
					return
				}
			} else {
				replyDNSTXT(w, r, query, "invalid format")
				return
			}
		}

		data := strings.ReplaceAll(str[:index], ".", "")
		cache, ok := caches.Load(messageID)
		if !ok {
			replyDNSTXT(w, r, query, "ok")
			return
		}
		cacheStr := cache.(string)
		cacheStr = cacheStr + data
		if str[index+1] == '1' {
			base32Enc := cacheStr

			padCount := (8 - len(base32Enc)%8) % 8
			padString := strings.Repeat("=", padCount)
			base32Enc = base32Enc + padString

			msg, err := base32.StdEncoding.DecodeString(base32Enc)
			caches.Delete(messageID)
			if err != nil {
				replyDNSTXT(w, r, query, "invalid format")
				return
			}
			msgChan <- string(msg)

			replyDNSTXT(w, r, query, "ok")
			return
		} else if str[index+1] == '0' {
			caches.Store(messageID, cacheStr)
			replyDNSTXT(w, r, query, "ok")
			return
		} else {
			replyDNSTXT(w, r, query, "invalid format")
			return
		}
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
func ListenAndServer(baseDomain string) chan string {
	// 创建DNS服务器
	server := &dns.Server{
		Addr: ":53", // 监听 53 端口
		Net:  "udp", // 使用 UDP 协议
	}
	// 注册 DNS 查询处理器
	dns.HandleFunc(".", func(w dns.ResponseWriter, m *dns.Msg) {
		handleDNSRequest(w, m, baseDomain)
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
