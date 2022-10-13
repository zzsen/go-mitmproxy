### 实现功能

1. 在`request`阶段前, 根据路由正则`regex`进行请求转发
2. 在`response`阶段, 根据`contentType`对 response 的 body 进行改写
   > 头部的 contentType 满足配置中的`regex`或头部的 contentType 和配置中的`contentType`一致

### 相关脚本

1. 直接启动 `go run main.go`
2. 打包成 exe 后启动 `go build`
   > 如需制定打包路径和生成的 exe 名称, 则加上`[-o 文件名]`, 默认是当前路径下的`go-mitmproxy.exe`

### 启动参数

| 参数                  | 说明                                                                     | 默认值              | 依赖 |
| --------------------- | ------------------------------------------------------------------------ | ------------------- | ---- |
| --version             | 输出 go-mitmproxy 的版本                                                 | false               | -    |
| --addr                | 监听地址和端口                                                           | :9998               | -    |
| --web_addr            | 可视化网页地址                                                           | :9999               | -    |
| --proxy_config_path   | 代理转发策略配置路径                                                     | ./proxy.json        | -    |
| --cert_path           | 证书地址                                                                 | .mitmproxy          | -    |
| --stream_large_bodies | (规划中, 暂未支持)当请求或响应体大于此字节时，转为 stream 模式, 默认 5mb | 5,242,880           | -    |
| --logPath             | 日志路径                                                                 | ./log/mitmproxy.log | -    |

### 证书安装

服务启动后, 会在`cert_path`参数指定的路径下生成证书, 双击证书`mitmproxy-ca-cert.cer`进行安装, 安装在`受信任的根证书颁发机构`

> 安装后, windows 下可以在 cmd 窗口中输入`certmgr`, 打开证书管理, 查看`受信任的根证书颁发机构`下, 是否存在`颁发者`和`颁发给`都是`mitmproxy`的证书

### 代理转发策略配置

代理转发策略配置路径由启动参数中的`--config_path`决定, 默认是当前路径下的`proxy.json`, 配置以 json 的格式存放的`ProxyStrategy`数组, 数组的数据结构如下:

```go
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
```

| 参数             | 数据类型 | 默认值 | 说明                                                                                                                                                                   |
| ---------------- | -------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| type             | string   | -      | 转发协议作用域, 可选: "request", "response"                                                                                                                            |
| contentType      | string   | -      | 转发内容类型, 根据 response 的 header 的 content-type 进行转发 (和 regex 二选一为必填)                                                                                 |
| regex            | string   | -      | 转发地址正则 (和 contentType 二选一为必填)                                                                                                                             |
| host             | string   | -      | 转发地址 host, 为空则直接请求原目标地址                                                                                                                                |
| scheme           | string   | -      | 转发协议, 为空则使用原请求协议                                                                                                                                         |
| path             | string   | -      | 转发地址路径, 为空则使用原请求路径                                                                                                                                     |
| method           | string   | -      | 请求方式, 为空则使用原请求方式                                                                                                                                         |
| originInfo2Query | bool     | false  | 原请求信息拼接到 query 内, 格式: `fmt.Sprintf("method=%s&scheme=%s&host=%s&path=%s&query=%s",【原 Method】, 【原 Scheme】, 【原 Host】, 【原 Path】, 【原 RawQuery】)` |

### 更多

fork from [lqqyt2423/go-mitmproxy](https://github.com/lqqyt2423/go-mitmproxy)<br/>
原 readme: [README.md](https://github.com/lqqyt2423/go-mitmproxy/blob/main/README.md)<br/>
原 readme(英文版): [README_EN.md](https://github.com/lqqyt2423/go-mitmproxy/blob/main/README_EN.md)
