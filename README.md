> 本 fork 含独立 [iOS 应用](apps/ios/README.md) 与 [移动端 core 源码](modules/mihomo-ios-core/SOURCE.md)。桌面端与移动端各自构建。见 [三端隐私架构](docs/three-platform-privacy.md)、[构建与 Release](docs/self-build.md)、[macOS 系统 DNS](docs/macos-system-dns.md)。

<h3 align="center">
  <img height='48px' src='./images/icon-white.png#gh-dark-mode-only'>
  <img height='48px' src='./images/icon-black.png#gh-light-mode-only'>
</h3>

<h3 align="center">基于 <a href="https://github.com/MetaCubeX/mihomo">Mihomo</a> 的 Clash Party 桌面端（个人 fork）</h3>

<p align="center">
  <a href="https://github.com/0xd3d/clash-party/releases">
    <img src="https://img.shields.io/github/release/0xd3d/clash-party/all.svg">
  </a>
</p>

<div align="center">
<img width="90%" src="./images/preview.jpg" alt="preview">
</div>

### 分支与发布

- 主开发分支：**`smart_core`**
- 推送该分支会构建 Pre-release（如 `v2.0.4-fork.N`）；产物与校验见 [Releases](https://github.com/0xd3d/clash-party/releases)
- 本地构建与更新源说明见 [docs/self-build.md](docs/self-build.md)

### 相对上游的侧重

- macOS **系统 DNS 接管 / 防旁路**、TUN 与隐私相关策略（见 `docs/`）
- **Smart Core** 规则覆写与国内应用分流等定制（见仓库内配置与 `changelog.md`）

### 特性（继承自上游桌面端）

- Smart Core 规则覆写、Mihomo / Smart 双内核
- Tun、覆写、Sub-Store、WebDAV 配置备份等上游已有能力
- 多种主题与常用 Mihomo 配置项图形化编辑

### 免责声明

本项目仅供学习与自用代理管理。请遵守当地法律法规；节点、订阅与使用策略由使用者自行负责。
