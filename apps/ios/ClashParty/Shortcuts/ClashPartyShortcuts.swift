import AppIntents

struct StartClashPartyVPNIntent: AppIntent {
  static var title: LocalizedStringResource = "Start Clash Party VPN"
  static var description = IntentDescription(
    LocalizedStringResource(
      "shortcuts.start.description",
      defaultValue: "Starts the packet tunnel with the last published Clash Party profile."
    )
  )
  static var openAppWhenRun = false

  func perform() async throws -> some IntentResult {
    try await TunnelShortcutService.startVPN()
    return .result()
  }
}

struct StopClashPartyVPNIntent: AppIntent {
  static var title: LocalizedStringResource = "Stop Clash Party VPN"
  static var description = IntentDescription(
    LocalizedStringResource(
      "shortcuts.stop.description",
      defaultValue: "Stops the Clash Party packet tunnel."
    )
  )
  static var openAppWhenRun = false

  func perform() async throws -> some IntentResult {
    try await TunnelShortcutService.stopVPN()
    return .result()
  }
}

struct ConnectAndWaitClashPartyVPNIntent: AppIntent {
  static var title: LocalizedStringResource = "Connect and wait for Clash Party VPN"
  static var description = IntentDescription(
    LocalizedStringResource(
      "shortcuts.connect_wait.description",
      defaultValue:
        "Starts the VPN when needed, then waits until international traffic readiness is green—the same standard as the in-app banner. Use in App automations before opening a sensitive app."
    )
  )
  static var openAppWhenRun = false

  @Parameter(title: "Timeout (seconds)", default: 60)
  var timeoutSeconds: Int

  func perform() async throws -> some IntentResult & ReturnsValue<Bool> {
    let timeout = TimeInterval(min(max(timeoutSeconds, 5), 180))
    let ready = try await TunnelShortcutService.connectAndWait(timeout: timeout)
    return .result(value: ready)
  }
}

struct OpenGoogleSafelyIntent: AppIntent {
  static var title: LocalizedStringResource = "Open Google with Clash Party VPN"
  static var description = IntentDescription(
    LocalizedStringResource(
      "shortcuts.open_google.description",
      defaultValue:
        "Connects and waits until international traffic is ready, then opens https://www.google.com. Pin this to the Home Screen instead of the Google app for the safest cold-start path."
    )
  )
  /// Needed so the system allows opening Safari after the VPN is ready.
  static var openAppWhenRun = true

  @Parameter(title: "Timeout (seconds)", default: 60)
  var timeoutSeconds: Int

  func perform() async throws -> some IntentResult & ReturnsValue<Bool> {
    let timeout = TimeInterval(min(max(timeoutSeconds, 5), 180))
    guard let url = URL(string: "https://www.google.com") else { return .result(value: false) }
    let opened = try await TunnelShortcutService.openURLWhenReady(url, timeout: timeout)
    await TunnelShortcutService.deliverPendingShortcutOpenIfNeeded()
    return .result(value: opened)
  }
}

struct WaitForClashPartyVPNIntent: AppIntent {
  static var title: LocalizedStringResource = "Wait for Clash Party VPN"
  static var description = IntentDescription(
    LocalizedStringResource(
      "shortcuts.wait.description",
      defaultValue: "Waits until international traffic readiness is green (same as the in-app banner), or until the timeout expires."
    )
  )
  static var openAppWhenRun = false

  @Parameter(title: "Timeout (seconds)", default: 45)
  var timeoutSeconds: Int

  func perform() async throws -> some IntentResult & ReturnsValue<Bool> {
    let timeout = TimeInterval(min(max(timeoutSeconds, 5), 180))
    let ready = try await TunnelShortcutService.waitForVPNReady(timeout: timeout)
    return .result(value: ready)
  }
}

struct ClashPartyShortcuts: AppShortcutsProvider {
  static var appShortcuts: [AppShortcut] {
    AppShortcut(
      intent: StartClashPartyVPNIntent(),
      phrases: [
        "Start \(.applicationName) VPN",
        "Turn on \(.applicationName)",
        "打开\(.applicationName) VPN",
        "连接\(.applicationName)",
      ],
      shortTitle: LocalizedStringResource("shortcuts.start.short", defaultValue: "Start VPN"),
      systemImageName: "shield.lefthalf.filled.badge.checkmark"
    )
    AppShortcut(
      intent: StopClashPartyVPNIntent(),
      phrases: [
        "Stop \(.applicationName) VPN",
        "Turn off \(.applicationName)",
        "关闭\(.applicationName) VPN",
        "断开\(.applicationName)",
      ],
      shortTitle: LocalizedStringResource("shortcuts.stop.short", defaultValue: "Stop VPN"),
      systemImageName: "shield.slash"
    )
    AppShortcut(
      intent: WaitForClashPartyVPNIntent(),
      phrases: [
        "Wait for \(.applicationName) VPN",
        "等待\(.applicationName) VPN",
      ],
      shortTitle: LocalizedStringResource("shortcuts.wait.short", defaultValue: "Wait for VPN"),
      systemImageName: "hourglass"
    )
    AppShortcut(
      intent: ConnectAndWaitClashPartyVPNIntent(),
      phrases: [
        "Connect and wait for \(.applicationName) VPN",
        "Prepare \(.applicationName) VPN",
        "连接并等待\(.applicationName) VPN",
        "打开\(.applicationName)前先连VPN",
      ],
      shortTitle: LocalizedStringResource(
        "shortcuts.connect_wait.short",
        defaultValue: "Connect & wait"
      ),
      systemImageName: "shield.checkered"
    )
    AppShortcut(
      intent: OpenGoogleSafelyIntent(),
      phrases: [
        "Open Google with \(.applicationName)",
        "Safely open Google with \(.applicationName)",
        "用\(.applicationName)打开Google",
        "安全打开Google用\(.applicationName)",
      ],
      shortTitle: LocalizedStringResource(
        "shortcuts.open_google.short",
        defaultValue: "Open Google"
      ),
      systemImageName: "globe.americas.fill"
    )
  }
}