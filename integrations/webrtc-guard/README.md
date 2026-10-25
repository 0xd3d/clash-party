# WebRTC Guard（可选浏览器扩展）

此目录是独立的 Chromium Manifest V3 扩展。Chrome / Edge 在 Windows 和 macOS 共用同一份源码；它不会随 Clash Party 自动安装，也不会修改 Clash、系统代理或 VPN。

扩展只申请 `privacy` 权限，只使用 `privacy.network.webRTCIPHandlingPolicy`，将当前浏览器配置文件的普通窗口设置为 `disable_non_proxied_udp`。没有网页访问、标签页、历史记录、Cookie、存储权限，没有网络请求、遥测或 IP 收集。扩展并不启动代理；网络出口仍由你的代理与路由配置决定。

## 手动安装

1. 从 Clash Party 导出本目录到可长期保存的位置。
2. 在 Chrome 打开 `chrome://extensions`，或在 Edge 打开 `edge://extensions`。
3. 开启“开发者模式”，选择“加载已解压的扩展”，选中包含 `manifest.json` 的目录。
4. 点击扩展图标，分别查看普通窗口与隐身窗口的配置读取结果。

首次安装会尝试启用并复查设置。浏览器或企业策略锁定、其他扩展控制时会保持现状；弹窗会显示控制来源。后续启动及升级只检查现有设置，不重新夺取控制。可手动点击“启用”再次尝试。

“恢复”仅执行本扩展的 `clear({ scope: 'regular' })`，不会把 `default` 强写回去；此前的浏览器、策略或其他扩展设置可能重新生效。停用或卸载扩展也会撤销本扩展的控制。恢复后再次启动浏览器不会自动重新启用。该行为无需保存额外开关或隐私数据。

## 保护与兼容边界

- 只影响安装扩展的浏览器配置文件，不能保护其他浏览器或其他配置文件。
- 普通配置可能被隐身窗口继承，也可能存在隐身专用覆盖。弹窗单独调用 `get({ incognito: true })` 查询；读取失败会明确显示未确认。查询结果不是对所有实际隐身窗口的网络测试。需要使用隐身专用扩展能力时，还应在浏览器扩展详情中检查隐身授权。
- `disable_non_proxied_udp` 限制 WebRTC 使用未经代理的 UDP；在相应代理支持不足时可能退回 TCP，降低视频通话质量或使通话失败。它不等于禁用 WebRTC，也不承诺所有网站永远无法获知任何地址。
- TUN 和 DNS 劫持控制网络路径，浏览器设置控制 WebRTC 的接口与地址暴露；两者作用不同。应在自己的浏览器中验证 HTTP 出口、WebRTC 候选地址和 DNS 出口，而不是仅看扩展状态。
- 企业策略优先于扩展；其他扩展也可能接管设置。启用后必须读取值与控制权确认，不能只把 API 调用成功当作已保护。
- 此包使用 Chromium MV3 模块 service worker，最低 Chrome 96；Edge 应使用支持此 API 和 MV3 的桌面版本。未在 Windows / macOS 的真实浏览器安装验证。
- **Firefox 不兼容此 manifest。** Firefox 有对应的 `browser.privacy.network.webRTCIPHandlingPolicy`，但后台脚本声明及扩展签名分发需独立适配；这里不提供未经验证的 Firefox 安装包。Firefox 专有的 `proxy_only` 也不作为跨浏览器默认值。
- Clash Party 的 Electron `setWebRTCIPHandlingPolicy` 仅作用于其自身 WebContents，不能替代这个外部浏览器扩展。

源码和测试不访问浏览器用户数据。开发验证：`pnpm exec vitest run scripts/webrtc-guard.test.ts`。

官方参考：[Chrome privacy API](https://developer.chrome.com/docs/extensions/reference/api/privacy)、[设置范围、恢复及优先级](https://developer.chrome.com/docs/extensions/reference/api/types)、[Firefox privacy API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/privacy/network)、[Electron WebContents](https://www.electronjs.org/docs/latest/api/web-contents#contentssetwebrtciphandlingpolicypolicy)。
