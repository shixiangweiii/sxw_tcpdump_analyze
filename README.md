# 抓包看得懂

输入一个 host，把跟它之间的每一条 TCP 连接，从生到死画清楚。

不是「简化版 Wireshark」，而是回答一个具体问题：**我跟这个 host 之间的连接，到底是怎么建立的、怎么断的、中间出了什么事。**

## 它解决什么

抓完包不知道看什么，是新手最普遍的困境。Wireshark 给你一个平铺的包列表和一套过滤语法，
要看懂三次握手得自己在几百行里找。这个工具反过来：

- **先按连接分组**，一条连接一行，直接给结论徽章：`建连成功 · 正常关闭` / `被 RST 中断` / `SYN 无响应` / `握手未捕获`
- **再展开时序梯形图**，左客户端右服务端，每个包配一句人话：`客户端发起建连（SYN），起始编号 0`
- **序号双份显示**：相对序号从 0 开始（看得懂），括号里是原始序号（能跟 Wireshark 对账）
- **异常直接标出来**：重传、快速重传、疑似乱序、零窗口、重复确认、丢段
- **明文 HTTP 直接还原报文**：请求行、响应头、正文（自动解块、按 charset 解码），
  并给出耗时分解 `请求送达 41.79ms / 服务端处理 8.42ms / 响应传输 48.81ms`——
  内网排查最常吵的「是网络慢还是服务端慢」，这一行就能定案。
  服务端把确认捎在响应首包上时（内网快链路的常态）两个时间点重合，
  界面会如实说明「处理时间测不出来」，而不是显示成 0

## 快速开始

```bash
npm install
npm run dev
```

浏览器打开 http://localhost:5173，把 pcap 拖进去。

想先拿样例试试：

```bash
npm run fixtures    # 生成 15 个合成抓包文件到 packages/core/fixtures/
```

## 怎么抓包

```bash
# 抓与某个 IP 之间的流量
sudo tcpdump -i any host 93.184.216.34 -w capture.pcap

# k8s pod 里
tcpdump -i any -w /tmp/capture.pcap

# 想让域名也能被识别，把 DNS 一起抓上
sudo tcpdump -i any 'host 93.184.216.34 or port 53' -w capture.pcap
```

## 关于 host 输入

支持 **IP** 和**域名**两种输入。域名要能用，前提是抓包里存在证据，按可靠性排序：

| 证据来源 | 说明 |
|---|---|
| DNS 应答 | 最可靠。会跟随 CNAME 链，`www.baidu.com` 和中间的 `www.a.shifen.com` 都能查到 |
| TLS SNI | HTTPS 下 ClientHello 仍是明文，SNI 在里面。抓包晚于 DNS 时的主要兜底 |
| HTTP Host 头 | 只有明文 HTTP 才有 |

界面会列出**自动发现的 host**并标明每条域名映射的来源，不需要你凭空猜要输入什么。

**k8s Service 名（如 `chat-svc`）暂不支持**——这个名字基本不出现在 TCP 包里，
实际链路是 DNS 解析成 ClusterIP、再被 kube-proxy DNAT 成 Pod IP，只能靠抓包里恰好有 DNS 查询才能还原。

## 关于抓包位置

在自己机器、k8s pod、nginx 服务端抓包都可以，**不需要配置视角**。

「发 SYN 的一方是客户端」这条规则在三种位置下都成立。工具会自动判断你查的 host
落在连接的哪一侧，界面上直接写明是「发往 X」还是「来自 X」。

## 结论的可信度

抓不到握手时（长连接、连接池，nginx 上尤其常见），有些数字是不可靠的，界面会明确标出来：

- 相对序号变成 `seq≈0`，表示基准是拿抓到的第一个包估算的
- 窗口值变成 `win=502?`，因为缩放因子在握手里协商，抓不到就无法换算
- 但**零窗口的判定不受影响**——窗口字段为 0 时，左移多少位都还是 0

乱序和重传在包层面几乎无法严格区分，只能靠时间间隔猜，所以乱序**一律标「疑似」**，不下确定结论。

同样的原则用在 HTTP 上：只有起始行真的长得像 HTTP（带 `HTTP/x.y` 版本号）才会还原报文。
像 Redis 内联命令 `GET mykey` 这种「大写方法 + 空格」的其他文本协议，宁可报「没有识别出应用层协议」，
也不会编出一条假报文——编造结论比不给结论更有害。

## 正确性校验

「自动给结论」的前提是结论正确，否则对新手的伤害比 Wireshark 更大。两层保障：

```bash
npm test              # 30 个单测，覆盖各类边界场景
npm run verify:tshark # 与 tshark 的 tcp.analysis.* 字段逐包对账
```

对账脚本需要 tshark（`brew install wireshark`），没装会自动跳过。

## 工程结构

```
packages/
  core/     纯 TS，无 IO：pcap 解析 → 协议解码 → 连接重组 → 异常判定
    src/pcap/      经典 pcap 与 pcapng 容器（手写，不依赖第三方库）
    src/decode/    链路层 / IP / TCP / UDP / DNS / TLS SNI / HTTP 报文解析
    src/analyze/   连接跟踪、状态机、异常检测、流重组、HTTP 事务、人话注解、host 注册表
    src/testing/   合成 pcap 构造器与 15 个场景夹具
  server/   Fastify，上传与查询接口，内存态会话
  web/      Vite + React，四个视图，梯形图为手写 SVG
```

## 支持范围

**容器**：经典 pcap（`tcpdump -w`）、pcapng（Wireshark 默认另存格式）

**链路层**：以太网、`LINUX_SLL` / `LINUX_SLL2`（`tcpdump -i any`）、回环、裸 IP，支持 VLAN / QinQ 剥离

**网络层**：IPv4 完整；IPv6 基础（不含扩展头链）；IP 分片只标记不重组

**应用层**：明文 HTTP/1.x 完整还原（TCP 流重组 → 起始行与头部 → chunked 解块 → charset 解码）；
TLS 只识别不解密

**暂不支持**：k8s Service 名解析、HTTPS 解密、HTTP/2 与 gRPC、QUIC/HTTP3 内容分析、
HTTP 正文的 gzip/br 解压（会标明「正文是 gzip 压缩的」而不是显示乱码）
