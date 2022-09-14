package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	rawLog "log"
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
	debug           int
	version         bool
	certPath        string
	proxyConfigPath string

	addr         string
	webAddr      string
	ssl_insecure bool
}

func (config *Config) loadConfig() {
	flag.IntVar(&config.debug, "debug", 0, "debug mode: 1 - print debug log, 2 - show debug from")
	flag.BoolVar(&config.version, "version", false, "show version")
	flag.StringVar(&config.addr, "addr", ":9998", "proxy listen addr")
	flag.StringVar(&config.webAddr, "web_addr", ":9999", "web interface listen addr")
	flag.BoolVar(&config.ssl_insecure, "ssl_insecure", false, "not verify upstream server SSL/TLS certificates.")
	flag.StringVar(&config.certPath, "cert_path", ".mitmproxy", "path of generate cert files")
	flag.StringVar(&config.proxyConfigPath, "proxy_config_path", "./proxy.json", "path of proxy config files")
	flag.Parse()
}

var config Config

func (a *SetProxyStrategy) loadProxyConfig() {
	a.ProxyStrategys = []ProxyStrategy{}
	log.Infof("load proxy config from path: %s", config.proxyConfigPath)
	if config.proxyConfigPath == "" {
		return
	}

	jsonFile, err := os.Open(config.proxyConfigPath)

	if err != nil {
		log.Error("error occurs while opening proxy config file")
		return
	}
	defer jsonFile.Close()

	jsonData, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Error("error occurs while reading proxy config file")
		return
	}

	if err := json.Unmarshal(jsonData, &a.ProxyStrategys); err == nil {
		log.Info(a.ProxyStrategys)
	} else {
		log.Error("error occurs while parsing proxy config file")
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

func (a *SetProxyStrategy) Request(f *proxy.Flow) {
	method := f.Request.Method
	newUrl := url.URL{
		Scheme:   f.Request.URL.Scheme,
		Host:     f.Request.URL.Host,
		Path:     f.Request.URL.Path,
		RawQuery: f.Request.URL.RawQuery,
	}
	for _, p := range a.ProxyStrategys {
		if p.Type != "request" {
			continue
		}
		url := fmt.Sprintf("%s/%s", f.Request.URL.Host, f.Request.URL.Path)
		if matched, err := regexp.Match(p.Regex, []byte(url)); !matched || err != nil {
			continue
		} else {
			fmt.Println("*******match********", p)
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
			fmt.Println("## newUrl ##")
			fmt.Println(newUrl.String())
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
		fmt.Println(f.Response.Header.Get("Content-Type"))
		if matched, err := regexp.Match(p.Regex, []byte(f.Response.Header.Get("Content-Type"))); !matched || err != nil {
			continue
		} else if strings.EqualFold(p.ContentType, f.Response.Header.Get("Content-Type")) {
			continue
		} else {
			fmt.Println("*******match********", p)
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
			fmt.Println("## newUrl ##")
			fmt.Println(newUrl.String())

			proxyReq, err := http.NewRequest(method, newUrl.String(), bytes.NewReader(f.Request.Body))
			if err != nil {
				log.Errorf("get request error: ", err)
			}
			response, err := (&http.Client{}).Do(proxyReq)
			if err != nil {
				log.Errorf("get response error: ", err)
			}
			defer response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK {
				log.Errorf("parse response error: ", err)
			}
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Errorf("parse body error: ", err)
			}

			if response.Header.Get("Content-Type") == f.Response.Header.Get("Content-Type") {
				f.Response.Body = body
				f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
			} else {
				log.Infof("content differ from origin, origin: %s, but get: %s", f.Response.Header.Get("Content-Type"), response.Header.Get("Content-Type"))
			}

			break
		}

	}

}

func main() {
	config.loadConfig()

	if config.debug > 0 {
		rawLog.SetFlags(rawLog.LstdFlags | rawLog.Lshortfile)
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if config.debug == 2 {
		log.SetReportCaller(true)
	}
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	opts := &proxy.Options{
		Addr:              config.addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.ssl_insecure,
		CaRootPath:        config.certPath,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if config.version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	p.AddAddon(&proxy.LogAddon{})

	setProxyStrategyAddon := SetProxyStrategy{}
	setProxyStrategyAddon.loadProxyConfig()
	p.AddAddon(&setProxyStrategyAddon)

	p.AddAddon(web.NewWebAddon(config.webAddr))

	log.Fatal(p.Start())
}
