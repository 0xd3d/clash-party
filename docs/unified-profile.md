# 三端共用配置

同一份 JSON 文件可在新版 macOS、Windows 和 iOS 客户端导入；节点、代理组、DNS 与公共规则只维护一次。已有 YAML 仍可照常使用，不会自动迁移当前配置。桌面端使用标准模式。

## 使用

1. 从 [`examples/unified-profile.json`](../examples/unified-profile.json) 建立自己的私有文件。示例节点是保留测试地址，必须替换；真实凭据不要提交 GitHub。
2. `common` 放节点、代理组、DNS 等 Mihomo 配置；`rules` 按实际匹配顺序排列。每次更新修改 `revision`，它是可读版本标识，不是签名或防回滚凭证。
3. 执行 `pnpm exec tsx scripts/unified-profile.ts check /path/to/private.json`，检查三端能否生成配置。它不会连接节点或更改运行中的客户端。
4. 桌面端“订阅管理 → 本地文件”、iOS“导入配置 → Profile YAML”选择同一个 `.json` 文件，也可使用各端已有订阅 URL 入口读取同一来源。无需新增一套同步服务；URL 的认证、定时刷新仍由现有客户端功能负责。
5. 桌面端保留并使用现有“一键防护”完成本机权限和防护设置；导入策略不会自动开启原生权限。iOS 继续使用自身 Network Extension 设置。更新后的文件需由各设备刷新或重新导入，修改 Mac 本地文件不会自动推送到手机。

仅修改 `common.proxies` 即可维护节点 IP/密钥；规则使用稳定的节点/组名。文件本身含有凭据，只通过你控制的私有路径分发，不上传公共 Release。尚未升级的客户端可导入下列工具生成的普通 YAML：

```sh
pnpm exec tsx scripts/unified-profile.ts render /path/to/private.json windows /path/to/windows.yaml
pnpm exec tsx scripts/unified-profile.ts render /path/to/private.json macos /path/to/macos.yaml
pnpm exec tsx scripts/unified-profile.ts render /path/to/private.json ios /path/to/ios.yaml
```

工具拒绝覆盖既有输出，生成文件权限为当前用户可读写。生成的是策略文件，仍需客户端执行本机适配与原生防护配置。

## 允许的差异

默认字符串规则三端共用；确实只适用于某端的规则显式标注，不会自动丢弃：

```json
{
  "rule": "AND,((NETWORK,tcp),(PROCESS-NAME,QQMusic.exe),(GEOIP,CN)),DIRECT",
  "platforms": ["windows"]
}
```

iOS 无法使用桌面进程名。若某条桌面规则是必要业务例外，维护者需要补充已确认的域名/IP 规则，不能假定省略后效果相同。

`platforms.ios.rule-providers` 可逐个替换同名规则提供者，例如为 MRS 提供明确的 YAML 版本。替换值是完整 provider 定义；其它 provider 保留。值为 `null` 时显式移除该端不使用的 provider；若规则仍引用它，导入会失败。不同格式的远程规则集是否包含相同域名，必须由维护者确认。iOS 不会自动下载/展开整个桌面 MRS 或猜测等价规则。

`tun`、`dns.listen`、物理网卡、控制器端口、系统 DNS 恢复状态、PF/WFP 授权等不得放入 `common`。它们属于软件和本机设置。原生保护继续在现有运行配置生成流程中执行；国内 TCP、局域网、QQ 音乐精确 DNS 例外及公网 UDP 代理按实际规则保留。导入不会关闭既有防护。

## 校验与恢复

- `format: clash-party-unified`、`version: 1`；使用 JSON 语法（文件也可命名为 `.yaml`）。拒绝未知版本/字段、未知平台、非法规则和缺失或提前出现的 `MATCH`。
- iOS 明确拒绝未标注的进程规则和仍为 MRS 的规则提供者。后续使用既有移动内核兼容校验，不承诺支持所有桌面协议。
- 桌面端先生成临时候选并执行内核校验，保留原始共用文件。替换时保存相邻的 `.previous` 私有备份；激活失败恢复旧文件并尝试恢复旧运行配置。它不是无限版本历史。
- iOS 在改变编辑区前完成结构和现有兼容校验，保存旧工作区备份，并将原始共用文件留在 App Group 的 `imports` 中。共用 DNS 在本次导入中替换旧 DNS 控制项；会修改共用字段的旧 YAML 覆写必须先由用户处理，不能静默遮盖新规则。编辑区和普通导出显示适配后的 YAML；应继续维护外部共用源。真正的内核启动仍可能因资源、网络、权限失败，按现有阻断策略处理。
- **配置已导入、原生防护已确认、网络实测通过是三个不同结果。** 本功能不会输出“无泄漏”认证；网络、WebRTC 和断网保护仍需实际设备验证。

## CI/CD

`smart_core` 和 `feature/three-platform-privacy` 的代码更新触发 `Build and release`。发布要求桌面检查、四个原生架构包及复用的 iOS 构建全部成功。

iOS 作业先对同一组正常/拒绝样例比较 Swift 与 TypeScript 输出，再运行已有移动策略测试，编译未签名真机和模拟器应用。Release 同时包含 Windows x64/ARM64、macOS Intel/Apple Silicon、iOS 未签名真机与 ARM64 模拟器归档、校验和及对应提交清单。

iOS 真机归档不是可直接安装的 IPA，仍需私有开发者签名和 Network Extension/App Group 描述文件。CI 不接触个人设备、不启动本机代理、不包含节点凭据。
