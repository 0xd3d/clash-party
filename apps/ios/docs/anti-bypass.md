# iOS 接管与加密引导边界

系统 VPN 配置显式使用 `includeAllNetworks=true`、`excludeLocalNetworks=false` 和 `disconnectOnSleep=false`。这是先将应用流量交给 Packet Tunnel，再由内核按规则选择 DIRECT 或代理；国内直连不需要在系统层排除中国 IP。`includeAllNetworks` 生效时，Apple 忽略 `enforceRoutes`，不能把两者当作两道叠加保护，也不能把 `excludedRoutes` 当作防火墙或 provider socket 的安全边界。

Apple 仍保留 DHCP、门户认证、部分蜂窝和伴随设备等系统例外。本轮没有更改 APNs、蜂窝服务和设备调试通信的排除偏好。普通 Packet Tunnel 不是托管 Always On：不能保证开机前、用户关闭 VPN 或系统撤销配置后的持续阻断。应用不主动启用 On Demand，也不再清除已有的用户策略；只有显式启动操作会重新启用已关闭的 VPN 配置。

节点是 IP 时，启动引导不发 DNS 查询。域名节点只接受独立的 IP 地址 HTTPS DoH 端点，保留 URL 端口、路径和查询参数；代理分组片段不作为独立引导使用。RFC 8484 请求使用系统默认 CA 和主机名校验，不接受重定向、不发送 Cookie、不提供 UDP 53 或 `getaddrinfo` 回退。最多并发四个节点域名、预热128个候选，响应限 65535 字节，总期限 12 秒。每个候选独立记录结果，失败或未预热候选不会阻止已选 IP 节点启动，也不会删除或替换节点；实际选择到域名节点后由移动内核进行加密解析，失败即连接失败，不能降级到主解析器或系统 DNS。代理自身的连接和独立引导需要底层网络，不能经尚未建立的代理形成循环；provider 发起的 socket 在 `includeAllNetworks` 下的实际行为仍需真机验证。

最终运行配置中的 `nameserver`、`fallback` 和普通 `nameserver-policy` 仅保留加密端点，绑定到递归核验不含 DIRECT 的代理组或节点。自定义 HTTPS URL 的端口、路径、查询参数和传输选项保留；不能用于加密解析的明文业务上游改用既有加密默认值。缺少安全代理目标时验证失败，绕过验证生成的配置也使用 REJECT，而不直连。代理组失效或名称不存在时，移动内核直接报错，不把名称当成物理网卡再回退；业务 DoH 也不跟随重定向，避免降级 HTTP。 带动态 `use`/include-all 成员的组不视为已验证的 DNS 安全目标，仍保留配置并选择可验证静态目标；移动内核在 provider 为空或 filter/exclude-type/exclude-filter 筛空时固定返回 REJECT，不使用 COMPATIBLE/隐式直连，也不因空数组选择而崩溃。DNS URL 片段按实际 Go URL 解析语义只解码一次，移除导入的裸代理 token，最终安全出口 token 放最后；独立引导检查全部裸 token，不能靠最后一个 DIRECT 覆盖前面的未知代理。

只有两条授权 QQ 音频策略可使用 `https://doh.pub/dns-query#DIRECT`：`aqqmusic.tc.qq.com` 和 `+.stream.qqmusic.qq.com`。`qq.com` 等更宽策略没有此例外。显式 `.lan`/`.local` 名称解析仍可使用用户已有的本地 DNS；节点本身使用独立的 literal-IP HTTPS 引导，它是建立代理前的必要例外。启动时重新生成已保存配置，使旧版本的未绑定业务 DNS 不会仅因缓存继续生效。

所有路由模式都在原业务规则前先加入已知公共 DNS 域名/IP 和 53/853 端口代理规则，再加入局域网与本地发现 DIRECT，最后加入常见 STUN/TURN 端口及剩余公网 UDP 的代理规则；硬编码到路由器或 ULA 的 DNS 不会因为私网地址提前直连，而 SMB、非 DNS 局域网 UDP 和本地发现仍保留。国内网页、音乐 TCP、LAN 和 QQ 音频 DNS 例外保留。移动内核遇到缺失的已匹配目标或不支持 UDP 的选中代理时明确失败，不跳过安全规则落入 DIRECT；没有显式可用规则的 UDP 也不能使用隐式 DIRECT。其他 App 内置的已知 DoH 端点因此也会先匹配代理。未知服务把 DoH 或 TURN 隐藏在与普通国内内容共用的 TCP443 中时，不能在不解密 TLS 的情况下可靠区分；这里不做 MITM，也不承诺穷尽所有未来端点。端点 IP 的地理归属和 DNS 提供者的 anycast 递归位置也不能仅凭配置保证完全相同。

Apple 文档说明 `includeAllNetworks` 在 VPN 离开 connected、重连和网络切换阶段丢弃普通应用流量。已接管后如果内嵌内核启动失败或已运行内核停止，扩展会先对当前 flow 锁存双向丢包并清空待处理队列，保留系统网络/DNS设置和 VPN 会话；轻量存活检查每秒一次，旧会话的回调不能解除或影响新会话。错误仍显示为失败，VPN 保留连接状态供用户显式停止后重新连接；不静默启用 On Demand，也不无限自动重启。显式停止会正常清理保护和核心。若系统杀死整个扩展进程，扩展内的计时器和丢包代码无法继续执行，实际阻断取决于 iOS 的 `includeAllNetworks` 生命周期；不能把这称为覆盖开机、卸载、配置移除或用户关闭 VPN 的托管 Always On。

规则与 Geo 在线资源在 Packet Tunnel 内由现有内核 HTTP client 按规则出站，未就绪时使用 bundle/cache 或延后，不能直接下载绕过。Swift Geo 下载只允许主 App 进程执行，扩展内即使缺文件也不会创建 URLSession 作为回退。主 App 的订阅导入、手动规则和 Geo 下载沿用系统 URLSession，在 VPN 已连接时受系统接管；首次导入或 VPN 未连接时不能宣称已有 VPN 保护。本轮没有为了资源下载额外开放本地 HTTP 代理端口。

关闭内核 IPv6 时仍向 iOS 安装捕获用 IPv6 地址与默认路由，但不发布可用 IPv6 DNS。packetFlow 桥接在内核入口和写回系统两侧明确丢弃 IPv6，计数为 `droppedIPv6Packets`；这表示阻断，不表示 IPv6 可用。热加载禁用会清除队列中的 IPv6并保留 IPv4，启用等内核提交后再解除阻断；旧 flow 无法更改替换会话的策略。

本地验证使用 URLProtocol HTTPS mock、DNS 报文及伪 packetFlow，不启动真实 VPN。它覆盖错误回答、重定向、超大回复、超时、业务 DNS 代理失效不直连、精确 QQ/LAN 例外、IPv6 丢弃、内核失败双向阻断/队列清理和会话替换；generic iOS 无签名构建不等于真机验收。真机还须验证 Wi-Fi/蜂窝切换、IPv6/NAT64、局域网 DNS、APNs、后台内存和断开恢复。

参考：

- [Apple VPN 路由说明](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)
- [includeAllNetworks](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)
- [excludeLocalNetworks](https://developer.apple.com/documentation/networkextension/nevpnprotocol/excludelocalnetworks)
- [托管 Always-on 配置](https://support.apple.com/en-euro/guide/deployment/dep00e2509ce/web)

- [STUN 的标准端口与协议（RFC 8489）](https://www.rfc-editor.org/rfc/rfc8489.html)
- [DNSPod 公共 DoH 接入说明](https://docs.dnspod.cn/notices/mian-fei-ban-dot-dohbu-zai-gong-kai-ipjie-ru-de-gong-gao/)
