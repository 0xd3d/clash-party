# 打开 App 前自动连 VPN（快捷指令 / 自动化）

## 为什么不能像装 App 一样「直接同步自动化」？

Apple **不允许**第三方把「个人自动化」（例如「打开 Google 时运行」）静默写进手机。  
开发者能做的只有：

| 能同步 | 不能同步 |
|--------|----------|
| 安装/升级 App 后，**快捷指令 → App → Clash Party** 里出现所有动作 | **自动化** 规则本身（必须在本机快捷指令里点一次保存） |
| 用户把某个动作 **加到主屏幕 / 小组件** | 替你绑定「打开 Google App 时触发」而无需确认 |

最接近「自动打开 Google」且防漏的做法：**主屏幕只留「Open Google with Clash Party VPN」（安全打开 Google）**，不要点系统里的 Google App 图标。

---

Clash Party 在系统「快捷指令」里提供 **Connect and wait for Clash Party VPN**（中文系统里多为 **连接并等待 Clash Party VPN**）。  
另提供 **Open Google with Clash Party VPN**（**用 Clash Party 打开 Google** / **安全打开 Google**）：内部 = 连接并等待 → 短暂唤起 Clash Party（系统要求）→ 在 Safari 打开 `https://www.google.com`。若第一次未跳出浏览器，切回 Clash Party 即可补开。
它会：

1. 若未连接则 **Start VPN**；若已在连接/已连上则 **不重复 start**，只等待；
2. 等到与首页 **国际流量 Ready 绿横幅** 相同的标准；
3. 返回 **是/否**（true/false），供自动化分支使用。

安装或升级 App 后，用 **同一 Apple ID** 的 iPhone 会在「快捷指令 → App」分类里看到这些动作（无需打开主 App）。**首次使用前**请打开 Clash Party 一次，确保配置已发布。

## 方案 A（推荐）：主屏幕「安全打开 Google」

1. **快捷指令** → **App** → **Clash Party** → **Open Google with Clash Party VPN**
2. **⋯** → **添加到主屏幕**
3. 以后只点这个图标进 Google（不要点 Google App / 不要先开 Safari 再连 VPN）

安装 App 后动作列表会随签名包更新；**不需要**单独导入文件。

## 方案 B：Claude / Chrome 等原生 App（推荐手工捷径）

Claude **没有**内置「安全打开」动作，但用 **连接并等待 → 打开 App** 与 Chrome 一样稳：

1. **快捷指令** → **+** → 命名如「Claude via Clash Party」
2. **连接并等待 Clash Party VPN**（超时 **60** 秒）
3. **如果** 输出 **为** false → **显示通知**「未就绪」→ **停止此捷径**
4. **否则** → **打开 App** → 选 **Claude**
5. **⋯** → **添加到主屏幕**（以后只点此图标，不要先点 Claude 再连 VPN）

验收：在 Clash Party 诊断里搜 `claude` / `anthropic`，连接应为海外出口、**不应**出现 `DIRECT`。General 路由已将 `claude.app` 与 `claude.ai`、`anthropic.com` 同级代理。

Chrome 可同样写一条捷径；勿把 **在 Chrome 中搜索** 接在 Wait 的输出后面（那是文本，不是布尔分支）。

## 方案 C：打开 Google App / Chrome 时（个人自动化，需本机绑一次）

1. **快捷指令** → **自动化** → **+** → **App**
2. 选 **Google**（Bundle：`com.google.GoogleMobile`）或 **Chrome** → **打开** → **立即运行**
3. 添加 **连接并等待 Clash Party VPN**（60s）
4. **如果** 输出 **为** false → **显示通知**「未就绪」

说明：触发时 Google 可能已在加载，仍有竞态；国际站更推荐 **方案 A**；Claude 更推荐 **方案 B** 主屏幕捷径。

## 个人自动化：打开某 App 时（通用）

1. 打开 **快捷指令** → **自动化** → **+** → **App**。
2. 选择要保护的 App（例如 Safari、Chrome、X）。
3. 选 **打开** → **立即运行**（是否关闭「运行前询问」自行权衡）。
4. 添加动作：**连接并等待 Clash Party VPN**（超时建议 **60** 秒）。
5. **如果** 上一步的 **输出** **是** **false**：
   - **显示通知**：「Clash Party 未就绪，请勿访问国际站」；或
   - **振动** + **停止并运行** → **Stop Clash Party VPN**（可选，更保守）。
6. **否则**：不添加动作（目标 App 会继续打开）。

### 竞态说明

自动化在 **App 已打开** 时触发，若 App 立刻加载网页，可能在 `Wait` 完成前有极短裸连窗口。对国际站最稳的方式仍是：**用捷径「连上并等待 → 打开 URL」作为入口**（见 README Shortcuts 一节），而不是先点 Safari 图标。

## 推荐捷径：未就绪则不要继续

可另建一条捷径供自动化调用（与上面等价）：

1. **连接并等待 Clash Party VPN**（60s）
2. **如果** 输出 **为** false → **显示提醒** → **停止执行此捷径**
3. （自动化里无需再写 Start / Wait 两步）

## 离开 App 后断开（可选）

**自动化** → **App** → 同一 App → **关闭**（若系统提供）→ **Stop Clash Party VPN**。

若在 Clash Party **设置**里开启 **「断开 VPN 前确认」**，首页断开会出现提醒（先退出 Claude/Chrome 等）；快捷指令里的 **Stop VPN** 会被拒绝，请在 App 内断开。

开启 **「敏感流量活跃时拒绝断开」**（默认开）时，App 会读取嵌入式内核的**实时连接**，若仍有 Claude / Google / OpenAI 等主机在活跃，**直接拒绝断开**（不弹可确认的「仍要断开」），请先划掉对应 App 或等待连接结束。

## 断开 VPN 前确认（设置）

**设置 → App Settings**：

- **断开 VPN 前确认**：开启后首页点断开需二次确认；无法自动关闭其他 App，仅防手滑与提示退出敏感 App 的顺序。
- **敏感流量活跃时拒绝断开**（默认开）：首页点断开时会先查内核连接；若 Claude / Google 等仍活跃则弹出「暂时无法断开」，**不会**出现可确认的「仍要断开」。与「断开前确认」同时开启时，**先**走敏感拦截，通过后才出现确认框。

## iCloud 同步

- **App Intents** 随 App 安装出现在各设备，不单独同步。
- **个人自动化** 随 **快捷指令 iCloud 同步** 在 iPhone / Mac 间同步；在任一设备按上文创建即可。