# iOS 接管与加密引导边界

系统 VPN 配置显式使用 `includeAllNetworks=true`、`excludeLocalNetworks=false` 和 `disconnectOnSleep=false`。这是先将应用流量交给 Packet Tunnel，再由内核按规则选择 DIRECT 或代理；国内直连不需要在系统层排除中国 IP。`includeAllNetworks` 生效时，Apple 忽略 `enforceRoutes`，不能把两者当作两道叠加保护，也不能把 `excludedRoutes` 当作防火墙或 provider socket 的安全边界。

Apple 仍保留 DHCP、门户认证、部分蜂窝和伴随设备等系统例外。本轮没有更改 APNs、蜂窝服务和设备调试通信的排除偏好。普通 Packet Tunnel 不是托管 Always On：不能保证开机前、用户关闭 VPN 或系统撤销配置后的持续阻断。应用不主动启用 On Demand，也不再清除已有的用户策略；只有显式启动操作会重新启用已关闭的 VPN 配置。

节点是 IP 时，启动引导不发 DNS 查询。域名节点只接受独立的 IP 地址 HTTPS DoH 端点，保留 URL 端口、路径和查询参数；代理分组片段不作为独立引导使用。RFC 8484 请求使用系统默认 CA 和主机名校验，不接受重定向、不发送 Cookie、不提供 UDP 53 或 `getaddrinfo` 回退。最多并发四个节点域名、预热128个候选，响应限 65535 字节，总期限 12 秒。每个候选独立记录结果，失败或未预热候选不会阻止已选 IP 节点启动，也不会删除或替换节点；实际选择到域名节点后由移动内核进行加密解析，失败即连接失败，不能降级到主解析器或系统 DNS。代理自身的连接和独立引导需要底层网络，不能经尚未建立的代理形成循环；provider 发起的 socket 在 `includeAllNetworks` 下的实际行为仍需真机验证。

运行配置中的业务 DNS 和已声明的 DNS 例外仍属于配置策略。此启动修复不等于任意导入配置中的自定义明文 DNS 都被强制转换为经韩国的 DoH；使用维护的主配置并核验最终运行配置，才能确认业务 DNS 的目标出口。

规则与 Geo 在线资源在 Packet Tunnel 内由现有内核 HTTP client 按规则出站，未就绪时使用 bundle/cache 或延后，不能直接下载绕过。Swift Geo 下载只允许主 App 进程执行，扩展内即使缺文件也不会创建 URLSession 作为回退。主 App 的订阅导入、手动规则和 Geo 下载沿用系统 URLSession，在 VPN 已连接时受系统接管；首次导入或 VPN 未连接时不能宣称已有 VPN 保护。本轮没有为了资源下载额外开放本地 HTTP 代理端口。

关闭内核 IPv6 时仍向 iOS 安装捕获用 IPv6 地址与默认路由，但不发布可用 IPv6 DNS。packetFlow 桥接在内核入口和写回系统两侧明确丢弃 IPv6，计数为 `droppedIPv6Packets`；这表示阻断，不表示 IPv6 可用。热加载禁用会清除队列中的 IPv6并保留 IPv4，启用等内核提交后再解除阻断；旧 flow 无法更改替换会话的策略。

本地验证使用 URLProtocol HTTPS mock、DNS 报文及伪 packetFlow，不启动真实 VPN。它覆盖错误回答、重定向、超大回复、超时、IPv6 丢弃和会话替换；generic iOS 无签名构建不等于真机验收。真机还须验证 Wi-Fi/蜂窝切换、IPv6/NAT64、局域网 DNS、APNs、后台内存和断开恢复。

参考：

- [Apple VPN 路由说明](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)
- [includeAllNetworks](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)
- [excludeLocalNetworks](https://developer.apple.com/documentation/networkextension/nevpnprotocol/excludelocalnetworks)
- [托管 Always-on 配置](https://support.apple.com/en-euro/guide/deployment/dep00e2509ce/web)
