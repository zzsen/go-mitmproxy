package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/lqqyt2423/go-mitmproxy/web"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	version         bool
	certPath        string
	proxyConfigPath string

	addr         string
	webAddr      string
	ssl_insecure bool

	logPath string
}

func (config *Config) loadConfig() {
	flag.BoolVar(&config.version, "version", false, "show version")
	flag.StringVar(&config.addr, "addr", ":9998", "proxy listen addr")
	flag.StringVar(&config.webAddr, "web_addr", ":9999", "web interface listen addr")
	flag.BoolVar(&config.ssl_insecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&config.certPath, "cert_path", ".mitmproxy", "path of generate cert files")
	flag.StringVar(&config.proxyConfigPath, "proxy_config_path", "./proxy.json", "path of proxy config files")
	flag.StringVar(&config.logPath, "log_path", "./log/mitmproxy.log", "path of log")
	flag.Parse()
}

var config Config

func (a *SetProxyStrategy) loadProxyConfig() {
	a.ProxyStrategys = []ProxyStrategy{}
	Infof("load proxy config from path: %s", config.proxyConfigPath)
	if config.proxyConfigPath == "" {
		return
	}

	jsonFile, err := os.Open(config.proxyConfigPath)

	if err != nil {
		Error("error occurs while opening proxy config file")
		return
	}
	defer jsonFile.Close()

	jsonData, err := io.ReadAll(jsonFile)
	if err != nil {
		Error("error occurs while reading proxy config file")
		return
	}

	if err := json.Unmarshal(jsonData, &a.ProxyStrategys); err == nil {
		proxyContent, _ := json.Marshal(a.ProxyStrategys)
		Info("proxy content: ", string(proxyContent))
	} else {
		Error("error occurs while parsing proxy config file")
		return
	}
}

type ProxyStrategy struct {
	Type             string `json:"type"`
	ContentType      string `json:"contentType"`
	Regex            string `json:"regex"`
	Host             string `json:"host"`
	Path             string `json:"path"`
	Method           string `json:"method"`
	Scheme           string `json:"scheme"`
	OriginInfo2Query bool   `json:"originInfo2Query"`
}

type SetProxyStrategy struct {
	proxy.BaseAddon
	ProxyStrategys []ProxyStrategy // 代理策略
}

var fileLog *log.Logger
var consoleLog *log.Logger

func Info(args ...interface{}) {
	fileLog.Info(args...)
	consoleLog.Info(args...)
}
func Error(args ...interface{}) {
	fileLog.Error(args...)
	consoleLog.Error(args...)
}
func Fatal(args ...interface{}) {
	fileLog.Fatal(args...)
	consoleLog.Fatal(args...)
}
func Infof(format string, args ...interface{}) {
	fileLog.Infof(format, args...)
	consoleLog.Infof(format, args...)
}
func Errorf(format string, args ...interface{}) {
	fileLog.Errorf(format, args...)
	consoleLog.Errorf(format, args...)
}
func Fatalf(format string, args ...interface{}) {
	fileLog.Fatalf(format, args...)
	consoleLog.Fatalf(format, args...)
}

func InitLog(path string) (string, *os.File, error) {
	filePath := path
	logPath := []string{}
	tempPath := strings.Split(path, "/")
	for _, subPath := range tempPath {
		if subPath != "" {
			logPath = append(logPath, subPath)
		}
	}

	if len(logPath) == 0 {
		if path != "/" {
			logPath = []string{"."}
		}
	}

	if len(logPath) > 0 && strings.Contains(logPath[len(logPath)-1], ".log") {
		filePath = logPath[len(logPath)-1]
		logPath = logPath[:len(logPath)-1]
	} else {
		filePath = "mitmproxy.log"
	}

	filePath = strings.Join(logPath, "/") + "/" + filePath

	err := os.MkdirAll(strings.Join(logPath, "/"), 0666)
	if err != nil {
		return filePath, nil, err
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	return filePath, file, err
}

func (a *SetProxyStrategy) Request(f *proxy.Flow) {
	method := f.Request.Method
	newUrl := url.URL{
		Scheme:   f.Request.URL.Scheme,
		Host:     f.Request.URL.Host,
		Path:     f.Request.URL.Path,
		RawQuery: f.Request.URL.RawQuery,
	}

	Info("[request] proxy start: ", newUrl)

	for _, p := range a.ProxyStrategys {
		if p.Type != "request" {
			continue
		}
		url := fmt.Sprintf("%s/%s", f.Request.URL.Host, f.Request.URL.Path)
		if matched, err := regexp.Match(p.Regex, []byte(url)); !matched || err != nil {
			continue
		} else {
			pJson, _ := json.Marshal(p)
			Info("[request] proxy match rule: ", string(pJson))
			if p.Method != "" {
				method = strings.ToUpper(p.Method)
			}

			if p.Host != "" {
				newUrl.Host = p.Host
			}
			if p.OriginInfo2Query {
				newUrl.RawQuery = fmt.Sprintf("method=%s&scheme=%s&host=%s&path=%s&query=%s",
					f.Request.Method, f.Request.URL.Scheme, f.Request.Raw().Host, f.Request.URL.Path, f.Request.URL.RawQuery)
			}
			if p.Path != "" {
				newUrl.Path = p.Path
			}
			if p.Scheme != "" {
				newUrl.Scheme = p.Scheme
			}
			urlJson, _ := json.Marshal(newUrl)
			Info("[request] proxy new url: ", newUrl.String(), ", url info: ", string(urlJson))
			break
		}
	}
	f.Request.URL = &newUrl
	f.Request.Method = method
}

func (a *SetProxyStrategy) Response(f *proxy.Flow) {
	method := f.Request.Method
	newUrl := url.URL{
		Scheme:   f.Request.URL.Scheme,
		Host:     f.Request.URL.Host,
		Path:     f.Request.URL.Path,
		RawQuery: f.Request.URL.RawQuery,
	}
	for _, p := range a.ProxyStrategys {
		if p.Type != "response" {
			continue
		}
		if matched, err := regexp.Match(p.Regex, []byte(f.Response.Header.Get("Content-Type"))); !matched || err != nil {
			continue
		} else if strings.EqualFold(p.ContentType, f.Response.Header.Get("Content-Type")) {
			continue
		} else {
			pJson, _ := json.Marshal(p)
			Info("[response] proxy match: ", string(pJson))
			if p.Method != "" {
				method = strings.ToUpper(p.Method)
			}

			if p.Host != "" {
				newUrl.Host = p.Host
			}
			if p.OriginInfo2Query {
				newUrl.RawQuery = fmt.Sprintf("method=%s&scheme=%s&host=%s&path=%s&query=%s",
					f.Request.Method, f.Request.URL.Scheme, f.Request.Raw().Host, f.Request.URL.Path, f.Request.URL.RawQuery)
			}
			if p.Path != "" {
				newUrl.Path = p.Path
			}
			if p.Scheme != "" {
				newUrl.Scheme = p.Scheme
			}
			urlJson, _ := json.Marshal(newUrl)
			Info("[response] proxy new url: ", newUrl.String(), ", url info: ", string(urlJson))

			proxyReq, err := http.NewRequest(method, newUrl.String(), bytes.NewReader(f.Request.Body))
			if err != nil {
				Errorf("get request error: ", err)
			}
			response, err := (&http.Client{}).Do(proxyReq)
			if err != nil {
				log.Errorf("get response error: ", err)
			}
			defer response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				Errorf("parse response error: ", err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				Errorf("parse body error: ", err)
			}

			if response.Header.Get("Content-Type") == f.Response.Header.Get("Content-Type") {
				f.Response.Body = body
				f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
				Info("[response] same content-type, update response body")
			} else {
				Infof("[response] content differ from origin, origin: %s, but get: %s", f.Response.Header.Get("Content-Type"), response.Header.Get("Content-Type"))
			}

			break
		}

	}
}

func main() {
	// load config
	config.loadConfig()

	// init log
	fileLog = log.New()
	consoleLog = log.New()
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05", // 设置json里的日期输出格式
	})
	fileLog.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05", // 设置json里的日期输出格式
	})
	consoleLog.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05", // 设置json里的日期输出格式
		ForceColors:     true,
	})
	// InitLog("/")
	// InitLog("./")
	// InitLog("/test.log")
	// InitLog("./log")
	// InitLog("log")
	path, file, err := InitLog(config.logPath)
	if err != nil {
		Fatal("fail to init log, ", err)
	} else {
		Info("init log path succeed, path:", path)
	}
	log.SetOutput(file)
	fileLog.SetOutput(file)
	consoleLog.SetOutput(os.Stdout)

	// init proxy config
	opts := &proxy.Options{
		Addr:              config.addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.ssl_insecure,
		CaRootPath:        config.certPath,
	}
	fmt.Println("web interface start listen at : " + config.webAddr)
	fmt.Println("Proxy start listen at :" + config.addr)

	p, err := proxy.NewProxy(opts)
	if err != nil {
		Fatal(err)
	}

	if config.version {
		fmt.Println("go-mitmproxy version: " + p.Version)
		os.Exit(0)
	}

	// add addon
	p.AddAddon(&proxy.LogAddon{})

	setProxyStrategyAddon := SetProxyStrategy{}
	setProxyStrategyAddon.loadProxyConfig()
	p.AddAddon(&setProxyStrategyAddon)

	p.AddAddon(web.NewWebAddon(config.webAddr))

	log.Fatal(p.Start())
}
