import Foundation
import SwiftUI
import UIKit

enum ImportedConfigKind: String {
  case profileYAML
  case controlledYAML
  case appConfigJSON
  case overrideYAML
  case routingSnapshot
}

enum ProxyTemplatePreset: String, CaseIterable, Identifiable {
  case vlessRealityVision
  case vmessWebSocket
  case trojanTLS
  case shadowsocks
  case socks5
  case httpConnect

  var id: String { rawValue }

  var title: String {
    switch self {
    case .vlessRealityVision:
      return L10n.string("profiles.templates.vless.title", "VLESS Reality / XTLS")
    case .vmessWebSocket:
      return L10n.string("profiles.templates.vmess.title", "VMess WebSocket")
    case .trojanTLS:
      return L10n.string("profiles.templates.trojan.title", "Trojan TLS")
    case .shadowsocks:
      return L10n.string("profiles.templates.ss.title", "Shadowsocks")
    case .socks5:
      return L10n.string("profiles.templates.socks.title", "SOCKS5")
    case .httpConnect:
      return L10n.string("profiles.templates.http.title", "HTTP CONNECT")
    }
  }

  var subtitle: String {
    switch self {
    case .vlessRealityVision:
      return L10n.string(
        "profiles.templates.vless.subtitle",
        "Reality + Vision starter with XTLS fields preserved for Mihomo."
      )
    case .vmessWebSocket:
      return L10n.string(
        "profiles.templates.vmess.subtitle",
        "TLS WebSocket example for common airport-style subscriptions."
      )
    case .trojanTLS:
      return L10n.string(
        "profiles.templates.trojan.subtitle",
        "TLS-backed Trojan node with SNI and ALPN placeholders."
      )
    case .shadowsocks:
      return L10n.string(
        "profiles.templates.ss.subtitle",
        "AEAD starter for direct manual editing and validation."
      )
    case .socks5:
      return L10n.string(
        "profiles.templates.socks.subtitle",
        "Local or remote SOCKS5 endpoint definition."
      )
    case .httpConnect:
      return L10n.string(
        "profiles.templates.http.subtitle",
        "Plain HTTP proxy definition for compatibility testing."
      )
    }
  }

  var icon: String {
    switch self {
    case .vlessRealityVision:
      return "lock.shield"
    case .vmessWebSocket:
      return "network"
    case .trojanTLS:
      return "shield.lefthalf.filled"
    case .shadowsocks:
      return "sparkles"
    case .socks5:
      return "point.3.connected.trianglepath.dotted"
    case .httpConnect:
      return "globe"
    }
  }

  var nodeName: String {
    switch self {
    case .vlessRealityVision:
      return "VLESS-Reality"
    case .vmessWebSocket:
      return "VMess-WS"
    case .trojanTLS:
      return "Trojan-TLS"
    case .shadowsocks:
      return "Shadowsocks-AEAD"
    case .socks5:
      return "SOCKS5-Proxy"
    case .httpConnect:
      return "HTTP-Proxy"
    }
  }

  var proxyBlock: String {
    rawProxyBlock
      .split(separator: "\n", omittingEmptySubsequences: false)
      .map { "  \($0)" }
      .joined(separator: "\n")
  }

  private var rawProxyBlock: String {
    switch self {
    case .vlessRealityVision:
      return """
      - name: \(nodeName)
        type: vless
        server: example.com
        port: 443
        uuid: 11111111-1111-1111-1111-111111111111
        network: tcp
        tls: true
        udp: true
        flow: xtls-rprx-vision
        servername: www.microsoft.com
        reality-opts:
          public-key: REPLACE_WITH_PUBLIC_KEY
          short-id: ""
          support-x25519mlkem768: true
        client-fingerprint: chrome
      """
    case .vmessWebSocket:
      return """
      - name: \(nodeName)
        type: vmess
        server: example.com
        port: 443
        uuid: 11111111-1111-1111-1111-111111111111
        alterId: 0
        cipher: auto
        tls: true
        udp: true
        servername: example.com
        network: ws
        ws-opts:
          path: /ws
          headers:
            Host: example.com
      """
    case .trojanTLS:
      return """
      - name: \(nodeName)
        type: trojan
        server: example.com
        port: 443
        password: REPLACE_WITH_PASSWORD
        tls: true
        udp: true
        sni: example.com
        alpn:
          - h2
          - http/1.1
      """
    case .shadowsocks:
      return """
      - name: \(nodeName)
        type: ss
        server: example.com
        port: 8388
        cipher: 2022-blake3-aes-128-gcm
        password: REPLACE_WITH_PASSWORD
        udp: true
      """
    case .socks5:
      return """
      - name: \(nodeName)
        type: socks5
        server: 127.0.0.1
        port: 1080
        username: ""
        password: ""
        udp: true
      """
    case .httpConnect:
      return """
      - name: \(nodeName)
        type: http
        server: 127.0.0.1
        port: 8080
        username: ""
        password: ""
        tls: false
      """
    }
  }

  var starterBundle: String {
    """
    proxies:
    \(proxyBlock)
    proxy-groups:
      - name: PROXY
        type: select
        proxies:
          - \(nodeName)
          - DIRECT
    rules:
      - MATCH,PROXY
    """
  }
}

private enum RemoteImportError: LocalizedError {
  case emptyURL
  case invalidURL
  case unsupportedScheme
  case httpStatus(Int)
  case emptyPayload

  var errorDescription: String? {
    switch self {
    case .emptyURL:
      return L10n.string("profiles.remote.error.empty", "Subscription URL is empty.")
    case .invalidURL:
      return L10n.string("profiles.remote.error.invalid", "Subscription URL is invalid.")
    case .unsupportedScheme:
      return L10n.string("profiles.remote.error.scheme", "Only http and https subscription URLs are supported.")
    case .httpStatus(let statusCode):
      return L10n.format("profiles.remote.error.http", "Remote server returned HTTP %d.", statusCode)
    case .emptyPayload:
      return L10n.string("profiles.remote.error.payload", "Remote subscription returned an empty payload.")
    }
  }
}

private enum TunnelInteractionLock {
  case starting
  case stopping
}

private struct DerivedStateInput: Equatable {
  let profileYaml: String
  let controlledConfigYaml: String
  let appConfigJson: String
  let overrideYaml: String
  let overrideJavaScript: String

  init(
    profileYaml: String,
    controlledConfigYaml: String,
    appConfigJson: String,
    overrideYaml: String,
    overrideJavaScript: String
  ) {
    self.profileYaml = profileYaml
    self.controlledConfigYaml = controlledConfigYaml
    self.appConfigJson = appConfigJson
    self.overrideYaml = overrideYaml
    self.overrideJavaScript = overrideJavaScript
  }

  var compatibilityInput: CompatibilityInput {
    CompatibilityInput(profileYaml: profileYaml, controlledConfigYaml: controlledConfigYaml,
      appConfigJson: appConfigJson, overrideYaml: overrideYaml, overrideJavaScript: overrideJavaScript)
  }

  init(_ input: CompatibilityInput) {
    self.init(
      profileYaml: input.profileYaml,
      controlledConfigYaml: input.controlledConfigYaml,
      appConfigJson: input.appConfigJson,
      overrideYaml: input.overrideYaml,
      overrideJavaScript: input.overrideJavaScript
    )
  }
}

@MainActor
final class ConsoleViewModel: ObservableObject {
  private static let runtimeDiagnosticsWriteInterval: TimeInterval = 10
  private static let routeExplanationConnectionLimit = 80
  private static let proxyNodeDisplayLimit = 120
  private static let rulePreviewLimit = 60
  private static let logPreviewLimit = 40
  private static let logTimestampFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.locale = .current
    formatter.timeZone = .current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss ZZZZZ"
    return formatter
  }()

  @Published var draftProfileName: String {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var draftBackupName: String {
    didSet { refreshProfilesPresentation() }
  }
  @Published var exportBundleName: String = "clash-party-ios-export" {
    didSet { refreshSettingsPresentation() }
  }
  @Published var remoteProfileURL: String = ConsoleViewModel.defaultRemoteProfileURL {
    didSet { refreshProfilesPresentation() }
  }

  @Published var profileYaml: String = ConsoleViewModel.defaultProfile {
    didSet { refreshProfilesPresentation() }
  }
  @Published var controlledConfigYaml: String = ConsoleViewModel.defaultControlledConfig {
    didSet {
      refreshDnsPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var appConfigJson: String = ConsoleViewModel.defaultAppConfig {
    didSet { refreshSettingsPresentation() }
  }
  @Published private(set) var routingUpdateMessage: String?
  @Published private(set) var isUpdatingRoutingRules = false

  var routingPolicy: IOSRoutingPolicy { RoutingPolicyService.preference(in: appConfigJson) }
  @Published private(set) var effectiveRoutingPolicy: IOSRoutingPolicy = .profile
  @Published private(set) var desktopRoutingSnapshot = RoutingPolicyService.loadDesktopSnapshot()

  func setRoutingPolicy(_ policy: IOSRoutingPolicy) {
    guard !isBusy, !isUpdatingRoutingRules else { return }
    do { try applyRoutingPolicy(policy) }
    catch { lastError = error.localizedDescription }
  }

  private func applyRoutingPolicy(_ policy: IOSRoutingPolicy) throws {
    var input = currentInput()
    input.appConfigJson = try RoutingPolicyService.setting(policy, in: input.appConfigJson)
    let report = compatibilityService.validate(input)
    guard report.isValid else {
      validationReport = report
      throw NSError(domain: "ClashParty.Routing", code: 1, userInfo: [NSLocalizedDescriptionKey: report.blockingErrors.joined(separator: "\n")])
    }
    appConfigJson = input.appConfigJson
    lastPublishedInput = nil
    applyWorkspaceDerivedStateSynchronously(for: input)
    validationReport = report
    schedulePersistImportedWorkspace(saveToProfileLibraryAfterPersist: false, reason: "Changed iOS routing policy to \(policy.rawValue).")
  }

  func refreshGeneralRoutingRules() {
    guard !isBusy, !isUpdatingRoutingRules else { return }
    isUpdatingRoutingRules = true
    routingUpdateMessage = L10n.string("routing.updating", "Updating rules…")
    Task {
      defer { isUpdatingRoutingRules = false }
      do {
        let home = try SharedStore.runtimeHomeURL()
        let runtimeConfig = compatibilityService.buildRuntimeConfig(from: currentInput())
        _ = try RoutingRuleResources.seedIfNeeded(runtimeConfig: runtimeConfig, homeURL: home)
        let errors = await RoutingRuleResources.refresh(homeURL: home)
        if errors.count < RoutingRuleResources.sources.count {
          await persistImportedWorkspace(reason: "Reloading refreshed iOS routing rule caches.", saveToProfileLibraryAfterPersist: false)
        }
        routingUpdateMessage = errors.isEmpty
          ? L10n.string("routing.updated", "Rules updated. Automatic checks run every 24 hours while the VPN is running.")
          : L10n.format("routing.update_partial", "%d rule sources failed; their last valid caches were retained.", errors.count)
        for error in errors { SharedStore.appendLog(level: "warning", message: "Routing rules update: " + error) }
      } catch {
        routingUpdateMessage = error.localizedDescription
      }
    }
  }
  @Published var overrideYaml: String = ConsoleViewModel.defaultOverrideYAML {
    didSet { refreshOverridePresentation() }
  }
  @Published var overrideJavaScript: String = ConsoleViewModel.defaultOverrideJavaScript {
    didSet { refreshOverridePresentation() }
  }

  @Published var runtimeStatus: RuntimeStatus = .init() {
    didSet { refreshOverviewPresentation() }
  }
  @Published var extensionSnapshot: TunnelExtensionSnapshot = .init() {
    didSet { refreshOverviewPresentation() }
  }
  @Published private(set) var sharedStoreDiagnostics = SharedStoreAppGroupDiagnostics(
    appGroupIdentifier: SharedStore.appGroupIdentifier,
    isAvailable: false,
    containerPath: nil,
    errorDescription: nil
  )
  @Published var validationReport: CompatibilityValidationReport = .init() {
    didSet { refreshSettingsPresentation() }
  }
  @Published var dnsSummary: DnsSummary = .init() {
    didSet {
      refreshDnsPresentation()
      refreshOverviewPresentation()
    }
  }
  @Published var tunSummary: TunSummary = .init() {
    didSet { refreshCorePresentation() }
  }
  @Published var mihomoSummary: MihomoSummary = .init() {
    didSet { refreshCorePresentation() }
  }
  @Published var subStoreSummary: SubStoreSummary = .init() {
    didSet { refreshSubStorePresentation() }
  }
  @Published private(set) var proxyGroups: [ProxyGroupSnapshot] = [] {
    didSet { refreshOverviewPresentation() }
  }
  @Published private(set) var displayedProxyGroups: [ProxyGroupSnapshot] = []
  @Published private(set) var displayedProxyNodes: [ProxyNodeRecord] = []
  @Published private(set) var routeExplanations: [RouteExplanation] = []
  @Published private(set) var proxiedRouteExplanationCount: Int = 0
  @Published private(set) var hiddenRouteExplanationCount: Int = 0
  @Published var proxyNodeSortMode: ProxyNodeSortMode = .profileOrder {
    didSet {
      proxyPresentationDeriver.invalidateSortCache()
      refreshDisplayedProxyNodes()
      refreshProxyPresentation()
    }
  }
  @Published var proxyNodes: [ProxyNodeRecord] = [] {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var rules: [RuleMatchRecord] = [] {
    didSet { refreshRulesPresentation() }
  }
  @Published var resources: [ResourceRecord] = [] {
    didSet { refreshResourcesPresentation() }
  }
  @Published var logs: [RuntimeLogEntry] = [] {
    didSet { refreshLogsPresentation() }
  }
  @Published var traffic: TrafficSnapshot = .init() {
    didSet { refreshOverviewPresentation() }
  }
  @Published private(set) var connections: [ConnectionSnapshot] = [] {
    didSet { refreshOverviewPresentation() }
  }
  @Published private(set) var proxyDelayStatuses: [String: ProxyDelayStatus] = [:]
  @Published private(set) var proxyDelayGroupsInFlight: Set<String> = []
  @Published var savedProfiles: [ProfileBundleRecord] = [] {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var backups: [BackupRecord] = [] {
    didSet { refreshProfilesPresentation() }
  }

  @Published var ruleCount: Int = 0 {
    didSet {
      refreshRulesPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var proxyCount: Int = 0 {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var version: String
  @Published var lastExportPath: String? {
    didSet {
      refreshSettingsPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var lastRemoteImportSource: String? {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var lastError: String? {
    didSet { refreshOverviewPresentation() }
  }
  @Published var activityMessage: String? {
    didSet { refreshShellPresentation() }
  }
  @Published var isBusy = false {
    didSet {
      refreshShellPresentation()
      refreshOverviewPresentation()
      refreshSubStorePresentation()
      refreshProfilesPresentation()
    }
  }
  @Published var isProfileEditorExpanded = false {
    didSet { refreshProfilesPresentation() }
  }
  @Published private(set) var isApplyingImportedWorkspace = false
  @Published private(set) var isTunnelInteractionLocked = false {
    didSet {
      refreshShellPresentation()
      refreshOverviewPresentation()
    }
  }

  let proxyPresentation = ProxyPresentationModel()
  let ruleInsightPresentation = RuleInsightPresentationModel()
  let shellPresentation = ShellPresentationModel()
  let overviewPresentation = OverviewPresentationModel()
  let connectionsPresentation = ConnectionsPresentationModel()
  let logsPresentation = LogsPresentationModel()
  let rulesPresentation = RulesPresentationModel()
  let dnsPresentation = DnsPresentationModel()
  let resourcesPresentation = ResourcesPresentationModel()
  let corePresentation = CorePresentationModel()
  let subStorePresentation = SubStorePresentationModel()
  let settingsPresentation = SettingsPresentationModel()
  let profilesPresentation = ProfilesPresentationModel()
  let overridePresentation = OverridePresentationModel()

  private let compatibilityService = CompatibilityService()
  private let runtime: RuntimeBridge = RuntimeBridgeFactory.makeAppBridge()
  private let runtimeIO: ConsoleRuntimeIO
  private let profileLibraryCoordinator = ConsoleProfileLibraryCoordinator()
  private var tunnelMonitorTask: Task<Void, Never>?
  private var proxyPreviewTask: Task<Void, Never>?
  private var derivedStateTask: Task<Void, Never>?
  private var refreshTask: Task<Void, Never>?
  private var profileLibraryRefreshTask: Task<Void, Never>?
  private var importedWorkspacePersistTask: Task<Void, Never>?
  private var geoResourceWarmupTask: Task<Void, Never>?
  private var proxySelectionState = ProxySelectionRuntimeState()
  private var tunnelInteractionLock: TunnelInteractionLock?
  private var didBootstrapWorkspace = false
  private var lastScenePhase: ScenePhase?
  private var lastAppActivityLeaseAt: Date?
  private var activeProfileRecordID: String? {
    didSet {
      refreshOverviewPresentation()
      refreshProfilesPresentation()
    }
  }
  private var lastRuntimeDiagnosticsWriteAt: Date?
  private var lastRuntimeDiagnosticsStatus: RuntimeStatus?
  private var lastRuntimeDiagnosticsExtensionSnapshot: TunnelExtensionSnapshot?
  private var lastRuntimeDiagnosticsProxyGroups: [ProxyGroupSnapshot]?
  private var lastRuntimeDiagnosticsDataPlaneSnapshot: RuntimeDataPlaneSnapshot?
  private var lastRuntimeDiagnosticsRouteExplanations: [RouteExplanation]?
  private var lastRuntimeDiagnosticsRouteExplanationMetrics: RouteExplanationMetrics?
  private var proxyGroupsByName: [String: ProxyGroupSnapshot] = [:]
  private var lastDerivedStateInput: DerivedStateInput?
  private var lastPublishedInput: CompatibilityInput?
  private var routeInsightDeriver = RouteInsightDeriver(limit: ConsoleViewModel.routeExplanationConnectionLimit)
  private var proxyPresentationDeriver = ProxyPresentationDeriver()
  private var proxyDelayTestingState = ProxyDelayTestingState()
  private var cachedDelayTestSettingsInput: String?
  private var cachedDelayTestSettings: DelayTestSettings = .init()
  private var refreshInFlight = false
  private var refreshPending = false
  private var refreshRequiresControllerSnapshot = false
  private var presentationRefreshBatchDepth = 0
  private var pendingProxyPresentationRefresh = false
  private var pendingRuleInsightPresentationRefresh = false
  private var pendingShellPresentationRefresh = false
  private var pendingOverviewPresentationRefresh = false
  private var pendingConnectionsPresentationRefresh = false
  private var pendingLogsPresentationRefresh = false
  private var pendingRulesPresentationRefresh = false
  private var pendingDnsPresentationRefresh = false
  private var pendingResourcesPresentationRefresh = false
  private var pendingCorePresentationRefresh = false
  private var pendingSubStorePresentationRefresh = false
  private var pendingSettingsPresentationRefresh = false
  private var pendingProfilesPresentationRefresh = false
  private var pendingOverridePresentationRefresh = false

  init() {
    draftProfileName = L10n.string("profiles.default_name", "Default Profile")
    draftBackupName = L10n.string("backups.default_name", "Local Backup")
    version = L10n.string("runtime.version.uninitialized", "Uninitialized")
    remoteProfileURL = Self.defaultRemoteProfileURL
    runtimeIO = ConsoleRuntimeIO(runtime: runtime)
    _ = verifySharedStoreAvailable()
    refreshShellPresentation()
    refreshOverviewPresentation()
    refreshConnectionsPresentation()
    refreshLogsPresentation()
    refreshRulesPresentation()
    refreshDnsPresentation()
    refreshResourcesPresentation()
    refreshCorePresentation()
    refreshSubStorePresentation()
    refreshSettingsPresentation()
    refreshProfilesPresentation()
    refreshOverridePresentation()
    refreshProxyPresentation()
    refreshRuleInsightPresentation()
  }

  deinit {
    tunnelMonitorTask?.cancel()
    proxyPreviewTask?.cancel()
    derivedStateTask?.cancel()
    refreshTask?.cancel()
    profileLibraryRefreshTask?.cancel()
    importedWorkspacePersistTask?.cancel()
    geoResourceWarmupTask?.cancel()
  }

  func bootstrap(restoreWorkspace: Bool = true) {
    guard !didBootstrapWorkspace else { return }
    didBootstrapWorkspace = true
    publishAppActivity(force: true)

    guard verifySharedStoreAvailable() else {
      validateOnly()
      return
    }

    Task {
      await TunnelManager.shared.prepareManagerForForeground()
    }

    if restoreWorkspace {
      restoreStartupWorkspaceAsync()
    }
    refreshProfileLibraryAsync()
    refresh()
    startMonitoringTunnelStatus()
  }

  #if DEBUG
  // Device-only validation uses an explicit launch argument and a local file.
  // Save the previous published workspace before selecting the test profile.
  func prepareDebugValidationProfile(fileName: String) async -> Bool {
    guard !fileName.isEmpty,
          fileName == URL(fileURLWithPath: fileName).lastPathComponent,
          let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
      return false
    }
    bootstrap(restoreWorkspace: false)
    isBusy = true
    defer { isBusy = false }
    do {
      let initial = await TunnelManager.shared.currentRuntimeObservation()
      if initial.runtimeStatus.vpnConnected || initial.runtimeStatus.state == .starting {
        try await TunnelManager.shared.stopTunnel()
        var stopped = false
        for _ in 0..<40 {
          try await Task.sleep(for: .milliseconds(250))
          let observation = await TunnelManager.shared.currentRuntimeObservation()
          if !observation.runtimeStatus.vpnConnected && observation.runtimeStatus.state == .stopped {
            stopped = true
            break
          }
        }
        guard stopped else {
          lastError = "The previous device validation tunnel did not stop in time."
          return false
        }
      }
      let workspace = await runtimeIO.loadStartupWorkspace(
        routeExplanationLimit: Self.routeExplanationConnectionLimit
      )
      let importedName = URL(fileURLWithPath: fileName).deletingPathExtension().lastPathComponent
      if let published = workspace.publishedBundle {
        let backup = try await profileLibraryCoordinator.createBackup(
          name: "Before importing \(importedName)",
          input: published.input,
          runtimeStatus: runtimeStatus
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(backup).write(
          to: documents.appendingPathComponent("profile-before-import-\(backup.id).json"),
          options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        )
      }
      let data = try Data(contentsOf: documents.appendingPathComponent(fileName))
      let input: CompatibilityInput
      if URL(fileURLWithPath: fileName).pathExtension.lowercased() == "json" {
        // A full bundle carries explicit DNS controls; do not replace them with
        // a legacy template or silently fall back when JSON decoding fails.
        input = try JSONDecoder().decode(CompatibilityInput.self, from: data)
      } else {
        input = CompatibilityInput(
          profileYaml: String(decoding: data, as: UTF8.self),
          controlledConfigYaml: Self.defaultControlledConfig,
          appConfigJson: Self.defaultAppConfig
        )
      }
      let report = compatibilityService.validate(input)
      guard report.isValid else {
        lastError = report.blockingErrors.joined(separator: "\n")
        return false
      }
      activeProfileRecordID = nil
      lastPublishedInput = nil
      apply(input)
      guard let saved = await persistCurrentInput(showBusy: false, refreshRuntimeSnapshot: false), saved.isValid else {
        return false
      }
      let record = try await profileLibraryCoordinator.upsertImportedProfile(
        input: input,
        fallbackName: importedName
      )
      activeProfileRecordID = record.id
      let published = try SharedStore.readPublishedConfigurationBundle()
      let effectiveDNS = compatibilityService.parseDnsSummary(from: published.runtimeConfig)
      let receipt: [String: Any] = [
        "profileName": importedName,
        "profileID": record.id,
        "generation": published.generation,
        "capturedAt": ISO8601DateFormatter().string(from: .now),
        "nameservers": effectiveDNS.nameservers,
        "proxyServerNameservers": effectiveDNS.proxyServerNameservers,
        "nameserverPolicyKeys": effectiveDNS.nameserverPolicyKeys,
        "rules": RoutingPolicyService.ruleStrings(in: published.runtimeConfig),
        "inputPreserved": published.input == compatibilityService.sanitizedMobileInput(input),
        "ipv6Captured": compatibilityService.makePacketTunnelNetworkPlan(from: published.runtimeConfig).ipv6Address != nil
      ]
      try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys])
        .write(to: documents.appendingPathComponent("profile-import-receipt.json"), options: [.atomic])
      SharedStore.appendLog(level: "info", message: "Debug profile bundle imported after preserving the previous workspace.")
      refreshProfileLibraryAsync()
      refresh()
      return true
    } catch {
      lastError = error.localizedDescription
      SharedStore.appendLog(level: "error", message: "Debug device validation profile failed: \(error.localizedDescription)")
      return false
    }
  }
  #endif

  private func restoreStartupWorkspaceAsync() {
    Task { [weak self] in
      guard let self else { return }
      let workspace = await runtimeIO.loadStartupWorkspace(
        routeExplanationLimit: Self.routeExplanationConnectionLimit
      )
      guard !Task.isCancelled else { return }

      self.performPresentationRefreshBatch {
        self.applyStartupWorkspace(workspace)
      }
      self.validateOnly()
    }
  }

  private func applyStartupWorkspace(_ workspace: ConsoleStartupWorkspace) {
    if let publishedBundle = workspace.publishedBundle {
      apply(
        publishedBundle.input,
        resetPreferredProxySelections: false,
        clearPersistedProxyGroups: false
      )
      lastPublishedInput = publishedBundle.input
      restoreActiveProfileIdentityIfPossible(for: publishedBundle.input)
    }
    proxySelectionState.loadPreferredSelections(workspace.proxySelectionPreferences)
    if routeExplanations != workspace.routeExplanations {
      routeExplanations = workspace.routeExplanations
    }
    routeInsightDeriver.seed(workspace.routeExplanations)
    let proxiedCount = RouteExplanationResolver.proxiedCount(in: workspace.routeExplanations)
    if proxiedRouteExplanationCount != proxiedCount {
      proxiedRouteExplanationCount = proxiedCount
    }
    refreshProxyPresentation()
    refreshRuleInsightPresentation()
    if workspace.publishedBundle != nil {
      warmupGeoResourcesIfNeeded(reason: "bootstrap")
    }
  }

  func refresh(refreshDerivedState: Bool = true, forceControllerSnapshotRefresh: Bool = false) {
    if refreshDerivedState {
      refreshDerivedStateAsync()
    }
    refreshPending = true
    refreshRequiresControllerSnapshot = refreshRequiresControllerSnapshot || forceControllerSnapshotRefresh
    guard !refreshInFlight else { return }

    refreshInFlight = true
    refreshTask = Task { [weak self] in
      guard let self else { return }
      defer {
        self.refreshInFlight = false
        self.refreshTask = nil
        if self.refreshPending {
          self.refresh(refreshDerivedState: false)
        }
      }

      while self.refreshPending, !Task.isCancelled {
        self.refreshPending = false
        let shouldForceControllerRefresh = self.refreshRequiresControllerSnapshot
        self.refreshRequiresControllerSnapshot = false
        await self.syncSystemTunnelStatus(
          forceControllerSnapshotRefresh: shouldForceControllerRefresh,
          scope: .fast
        )
      }
    }
  }

  private func refreshProfileLibraryAsync() {
    profileLibraryRefreshTask?.cancel()
    profileLibraryRefreshTask = Task { [weak self] in
      guard let self else { return }
      let snapshot = await self.profileLibraryCoordinator.loadLibrarySnapshot()
      guard !Task.isCancelled else { return }
      if self.savedProfiles != snapshot.profiles {
        self.savedProfiles = snapshot.profiles
      }
      if self.backups != snapshot.backups {
        self.backups = snapshot.backups
      }
    }
  }

  func refreshRouteInsight() {
    refreshDerivedStateAsync()
    Task { [weak self] in
      guard let self else { return }
      if let snapshot = await self.syncSystemTunnelStatus(forceControllerSnapshotRefresh: true) {
        self.noteEmptyRouteInsightSnapshotIfNeeded(snapshot)
      }
    }
  }

  func importConfig() {
    Task { [weak self] in
      guard let self else { return }
      _ = await self.persistCurrentInput(showBusy: true, refreshRuntimeSnapshot: true)
    }
  }

  func validateOnly() {
    validationReport = compatibilityService.validate(currentInput())
    refreshDerivedStateAsync()
  }

  func reloadRuntime() {
    guard !isBusy else { return }
    isBusy = true
    lastError = nil

    Task {
      defer { isBusy = false }
      do {
        try await runtimeIO.reloadRuntime()
        refresh()
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  private func warmupGeoResourcesIfNeeded(reason: String) {
    guard verifySharedStoreAvailable() else { return }
    let input = currentInput()
    geoResourceWarmupTask?.cancel()
    geoResourceWarmupTask = Task.detached(priority: .utility) {
      SharedStore.appendLog(
        level: "info",
        message: "Preparing GeoIP/GeoSite/MMDB/ASN resources in background for \(reason)."
      )
      let runtimeConfig = CompatibilityService().buildRuntimeConfig(from: input)
      await GeoResourceManager.refreshBuiltInResourcesIfNeeded(from: runtimeConfig)
    }
  }

  func startTunnel() {
    guard verifySharedStoreAvailable() else { return }
    guard tunnelInteractionLock == nil else {
      SharedStore.appendLog(
        level: "info",
        message: "App ignored a duplicate VPN connection attempt because the tunnel is already starting or stopping."
      )
      return
    }
    guard proxyCount > 0 else {
      lastError = L10n.string(
        "error.tunnel.no_proxy_nodes",
        "Import a profile with at least one proxy node before starting the VPN tunnel."
      )
      SharedStore.appendLog(
        level: "warning",
        message: "App refused to start the VPN tunnel because the current workspace does not contain any proxy nodes."
      )
      return
    }
    guard !isBusy else { return }
    setTunnelInteractionLock(.starting)
    isBusy = true
    lastError = nil
    SharedStore.appendLog(level: "info", message: "App requested a VPN connection attempt.")
    activityMessage = L10n.string(
      "tunnel.activity.starting",
      "Preparing VPN configuration and requesting iOS to start the tunnel."
    )
    warmupGeoResourcesIfNeeded(reason: "vpn-start")
    runtimeStatus.state = .starting
    runtimeStatus.vpnConnected = false
    runtimeStatus.startupPhase = "validatingConfig"
    runtimeStatus.startupMessage = L10n.string(
      "tunnel.phase.validating",
      "Validating the imported profile before starting the tunnel."
    )
    runtimeStatus.lastFailureReason = nil
    runtimeStatus.lastFailurePhase = nil
    runtimeStatus.lastStopReason = nil
    extensionSnapshot.lastFailureReason = nil
    extensionSnapshot.lastFailurePhase = nil
    extensionSnapshot.lastStopReason = nil

    Task {
      do {
        guard let report = await persistCurrentInput(showBusy: false, refreshRuntimeSnapshot: false) else {
          activityMessage = nil
          isBusy = false
          setTunnelInteractionLock(nil)
          return
        }
        guard report.isValid else {
          activityMessage = nil
          isBusy = false
          setTunnelInteractionLock(nil)
          return
        }
        try await TunnelManager.shared.startTunnel()
        activityMessage = runtimeStatus.startupMessage.isEmpty
          ? L10n.string(
            "tunnel.activity.waiting",
            "Tunnel start request sent. Waiting for iOS VPN status to change."
          )
          : runtimeStatus.startupMessage
        await syncSystemTunnelStatus()
        try? await Task.sleep(for: .seconds(1))
        await syncSystemTunnelStatus()
      } catch {
        lastError = error.localizedDescription
        activityMessage = nil
        setTunnelInteractionLock(nil)
      }
      refresh()
      if runtimeStatus.state == .running || runtimeStatus.state == .stopped || runtimeStatus.state == .failed {
        isBusy = false
        activityMessage = nil
      } else {
        isBusy = true
      }
    }
  }

  func clearLogs() {
    do {
      try SharedStore.clearLogs()
      logs = []
    } catch {
      lastError = error.localizedDescription
    }
  }

  func copyLogs() {
    guard !logs.isEmpty else { return }
    let serialized = logs.map { log in
      "\(formattedLogTimestamp(log.timestamp)) [\(log.level.uppercased())] \(log.message)"
    }.joined(separator: "\n")
    UIPasteboard.general.string = serialized
    activityMessage = L10n.string("logs.copy_success", "Logs copied to the clipboard.")
  }

  func formattedLogTimestamp(_ timestamp: Date) -> String {
    Self.logTimestampFormatter.string(from: timestamp)
  }

  func stopTunnel() {
    guard tunnelInteractionLock != .stopping else { return }
    setTunnelInteractionLock(.stopping)
    isBusy = true
    SharedStore.appendLog(level: "info", message: "App requested the VPN tunnel to stop.")
    activityMessage = L10n.string("tunnel.activity.stopping", "Stopping Packet Tunnel and releasing runtime resources.")

    Task {
      do {
        try await TunnelManager.shared.stopTunnel()
        await syncSystemTunnelStatus()
      } catch {
        lastError = error.localizedDescription
        activityMessage = nil
        setTunnelInteractionLock(nil)
      }
      refresh()
      isBusy = false
      activityMessage = nil
    }
  }

  private func publishAppActivity(force: Bool = false) {
    let now = Date()
    guard force || lastAppActivityLeaseAt.map({ now.timeIntervalSince($0) >= 15 }) ?? true else { return }
    try? SharedStore.recordAppActivity(AppActivityLease(isActive: (lastScenePhase ?? .active) == .active, updatedAt: now))
    lastAppActivityLeaseAt = now
  }

  func handleScenePhase(_ phase: ScenePhase) {
    guard lastScenePhase != phase else { return }
    lastScenePhase = phase
    publishAppActivity(force: true)

    let activity: String
    switch phase {
    case .active:
      activity = "active"
      if didBootstrapWorkspace {
        refresh()
        startMonitoringTunnelStatus()
      }
    case .inactive:
      activity = "inactive"
    case .background:
      activity = "background"
      tunnelMonitorTask?.cancel()
      tunnelMonitorTask = nil
    @unknown default:
      activity = "unknown"
    }

    SharedStore.appendLog(
      level: "info",
      message: "App scene changed to \(activity). Cached runtime state=\(runtimeStatus.state.rawValue) vpnConnected=\(runtimeStatus.vpnConnected) dataPlaneReady=\(runtimeStatus.dataPlaneReady). App-side status polling \(phase == .background ? "paused" : "enabled"); VPN forwarding remains managed by the Packet Tunnel extension."
    )
  }

  func startMonitoringTunnelStatus() {
    guard tunnelMonitorTask == nil, lastScenePhase != .background else { return }

    tunnelMonitorTask = Task { [weak self] in
      while !Task.isCancelled {
        self?.publishAppActivity()
        await self?.syncSystemTunnelStatus(scope: .fast)
        let interval: Duration
        if self?.runtimeStatus.state == .starting
          || self?.isBusy == true
          || self?.isTunnelInteractionLocked == true {
          interval = .seconds(1)
        } else if self?.runtimeStatus.state == .running || self?.extensionSnapshot.running == true {
          interval = .seconds(3)
        } else {
          interval = .seconds(5)
        }
        try? await Task.sleep(for: interval)
      }
    }
  }

  func selectProxy(group: ProxyGroupSnapshot, proxy: String) {
    guard ProxySelectionCoordinator.isSelection(proxy, validFor: group) else {
      lastError = L10n.string(
        "proxies.group.auto_managed",
        "This proxy group is managed automatically by the runtime and cannot be pinned manually."
      )
      SharedStore.appendLog(
        level: "info",
        message: "Ignored an invalid manual proxy selection '\(proxy)' for group '\(group.name)' because the controller snapshot does not expose it as a selectable option."
      )
      return
    }

    let request = ProxySelectionRequest(groupName: group.name, proxy: proxy)
    let alreadyQueued = proxySelectionState.contains(request)
    if confirmedSelection(for: group.name) == proxy && !alreadyQueued {
      return
    }

    lastError = nil
    storePreferredSelection(proxy, for: group.name)

    if proxySelectionState.active == request {
      return
    }

    guard runtimeCanAcceptProxySelectionSoon else {
      proxySelectionState.clearWaitReason()
      refreshProxyPresentation()
      SharedStore.appendLog(
        level: "info",
        message: "Saved proxy selection '\(proxy)' for group '\(group.name)' as the next-connect preference. The active runtime selection stays unchanged until the VPN becomes available again."
      )
      refresh(refreshDerivedState: false)
      return
    }

    proxySelectionState.queue(request)
    refreshProxyPresentation()
    processPendingProxySelectionIfNeeded()
  }

  func speedTest(group: ProxyGroupSnapshot) {
    let previewProxyNames = ProxyPresentationDeriver.uniqueProxyNames(
      from: group.displayOptions.isEmpty ? group.all : group.displayOptions
    )
    guard beginProxyGroupDelayTest(group.name, previewProxyNames: previewProxyNames) else { return }

    let delayTestSettings = resolvedDelayTestSettings(preferredURL: group.testURL)
    let probeURL = delayTestSettings.url
    let timeoutMilliseconds = delayTestSettings.timeoutMilliseconds
    lastError = nil
    SharedStore.appendLog(
      level: "info",
      message: "Started node speed test for group '\(group.name)' against \(probeURL)."
    )

    Task { [weak self] in
      guard let self else { return }

      defer {
        self.finishProxyGroupDelayTest(group.name)
        self.refresh(refreshDerivedState: false)
      }

      do {
        let delays = try await self.runtimeIO.measureGroupDelays(
          name: group.name,
          url: probeURL,
          timeoutMilliseconds: timeoutMilliseconds
        )

        let measuredProxyNames = self.applyProxyGroupDelayMeasurements(
          previewProxyNames: previewProxyNames,
          measurements: delays
        )
        self.mergeDiscoveredProxyNodes(named: measuredProxyNames)
        SharedStore.appendLog(
          level: "info",
          message: "Finished node speed test for group '\(group.name)' and received \(delays.count) delay measurements."
        )
      } catch {
        self.markProxyDelayStatuses(self.proxyDelayFailureStatus(for: error), for: previewProxyNames)
        self.lastError = error.localizedDescription
        SharedStore.appendLog(
          level: "warning",
          message: "Node speed test failed for group '\(group.name)': \(error.localizedDescription)"
        )
      }
    }
  }

  func speedTest(node: ProxyNodeRecord) {
    let proxyName = node.name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard beginProxyNodeDelayTest(proxyName) else { return }
    let delayTestSettings = resolvedDelayTestSettings(
      preferredURL: preferredDelayTestURL(for: proxyName)
    )
    let probeURL = delayTestSettings.url
    let timeoutMilliseconds = delayTestSettings.timeoutMilliseconds
    lastError = nil
    SharedStore.appendLog(
      level: "info",
      message: "Started node speed test for proxy '\(proxyName)' against \(probeURL)."
    )

    Task { [weak self] in
      guard let self else { return }

      do {
        let delay = try await self.runtimeIO.measureProxyDelay(
          name: proxyName,
          url: probeURL,
          timeoutMilliseconds: timeoutMilliseconds
        )
        self.applyProxyNodeDelayMeasurement(proxyName: proxyName, delay: delay)
        SharedStore.appendLog(
          level: "info",
          message: "Finished node speed test for proxy '\(proxyName)' with delay \(delay) ms."
        )
      } catch {
        self.failProxyNodeDelayTest(proxyName: proxyName, status: self.proxyDelayFailureStatus(for: error))
        self.lastError = error.localizedDescription
        SharedStore.appendLog(
          level: "warning",
          message: "Node speed test failed for proxy '\(proxyName)': \(error.localizedDescription)"
        )
      }
    }
  }

  private func preferredDelayTestURL(for proxyName: String) -> String? {
    let normalizedProxyName = proxyName.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedProxyName.isEmpty else { return nil }

    let groupContainsProxy: (ProxyGroupSnapshot) -> Bool = { group in
      group.all.contains {
        $0.trimmingCharacters(in: .whitespacesAndNewlines) == normalizedProxyName
      }
    }
    let selectedGroupTestURL = proxyGroups.first { group in
      guard groupContainsProxy(group) else { return false }
      let selectedProxy = confirmedSelection(for: group.name)
        ?? group.selected?
          .trimmingCharacters(in: .whitespacesAndNewlines)
        ?? ""
      return selectedProxy == normalizedProxyName
    }?.testURL

    if let selectedGroupTestURL,
       !selectedGroupTestURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      return selectedGroupTestURL
    }

    return proxyGroups.first(where: groupContainsProxy)?.testURL
  }

  private func resolvedDelayTestSettings(preferredURL: String?) -> DelayTestSettings {
    let appConfigSettings = cachedAppDelayTestSettings()
    let preferredProbeURL = preferredURL?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let fallbackProbeURL = appConfigSettings.url.trimmingCharacters(in: .whitespacesAndNewlines)

    return DelayTestSettings(
      url: !preferredProbeURL.isEmpty
        ? preferredProbeURL
        : (!fallbackProbeURL.isEmpty ? fallbackProbeURL : CompatibilityService.defaultDelayTestURL),
      timeoutMilliseconds: appConfigSettings.timeoutMilliseconds > 0
        ? appConfigSettings.timeoutMilliseconds
        : CompatibilityService.defaultDelayTestTimeoutMilliseconds
    )
  }

  private func cachedAppDelayTestSettings() -> DelayTestSettings {
    if cachedDelayTestSettingsInput == appConfigJson {
      return cachedDelayTestSettings
    }

    let settings = compatibilityService.parseDelayTestSettings(from: appConfigJson)
    cachedDelayTestSettingsInput = appConfigJson
    cachedDelayTestSettings = settings
    return settings
  }

  func saveCurrentProfile() {
    let remoteImportSource = lastRemoteImportSource?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let record: ProfileBundleRecord
    if !remoteImportSource.isEmpty {
      record = ProfileBundleRecord.recordForRemoteImport(
        remoteSource: remoteImportSource,
        input: currentInput(),
        existingRecords: savedProfiles,
        fallbackName: preferredRemoteProfileName(),
        now: .now
      )
    } else {
      record = ProfileBundleRecord(
        name: draftProfileName.isEmpty
          ? L10n.format("profiles.generated_name", "Profile %d", savedProfiles.count + 1)
          : draftProfileName,
        input: currentInput()
      )
    }
    lastError = nil

    Task { [weak self] in
      guard let self else { return }
      do {
        try await profileLibraryCoordinator.saveProfile(record)
        activeProfileRecordID = record.id
        draftProfileName = record.name
        lastRemoteImportSource = record.remoteSource
        refreshProfileLibraryAsync()
        refresh()
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func loadProfile(_ profile: ProfileBundleRecord) {
    apply(profile.input)
    activeProfileRecordID = profile.id
    draftProfileName = profile.name
    lastRemoteImportSource = profile.remoteSource
    if let remoteSource = profile.remoteSource,
       !remoteSource.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      remoteProfileURL = remoteSource
    }
    validateOnly()
    schedulePersistImportedWorkspace(
      reason: "Loaded the saved profile '\(profile.name)' and scheduled it for persistence."
    )
  }

  func deleteProfile(_ profile: ProfileBundleRecord) {
    let shouldClearActiveWorkspace = profile.matchesActiveWorkspace(
      input: currentInput(),
      remoteSource: lastRemoteImportSource,
      activeProfileID: activeProfileRecordID
    )
    lastError = nil

    Task { [weak self] in
      guard let self else { return }
      do {
        try await profileLibraryCoordinator.deleteProfile(id: profile.id)
        refreshProfileLibraryAsync()
        if shouldClearActiveWorkspace {
          clearActiveWorkspaceAfterDeletingProfile(profile)
          return
        }
        refresh()
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func createBackup() {
    let name = draftBackupName.isEmpty
      ? L10n.format("backups.generated_name", "Backup %d", backups.count + 1)
      : draftBackupName
    let input = currentInput()
    let status = runtimeStatus
    lastError = nil

    Task { [weak self] in
      guard let self else { return }
      do {
        _ = try await profileLibraryCoordinator.createBackup(
          name: name,
          input: input,
          runtimeStatus: status
        )
        refreshProfileLibraryAsync()
        refresh()
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func restoreBackup(_ backup: BackupRecord) {
    apply(backup.input)
    validateOnly()
    schedulePersistImportedWorkspace(
      reason: "Restored the backup '\(backup.name)' and scheduled it for persistence."
    )
  }

  func deleteBackup(_ backup: BackupRecord) {
    lastError = nil
    Task { [weak self] in
      guard let self else { return }
      do {
        try await profileLibraryCoordinator.deleteBackup(id: backup.id)
        refreshProfileLibraryAsync()
        refresh()
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func exportCurrentBundle() {
    validateOnly()
    let exportName = exportBundleName
    let input = currentInput()
    let status = runtimeStatus
    let report = validationReport
    lastError = nil

    Task { [weak self] in
      guard let self else { return }
      do {
        let url = try await profileLibraryCoordinator.exportCurrentBundle(
          name: exportName,
          input: input,
          runtimeStatus: status,
          validationReport: report
        )
        lastExportPath = url.path
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func probeSubStore() {
    let remoteURL = subStoreSummary.remoteURL
    guard let url = URL(string: remoteURL), !remoteURL.isEmpty else {
      subStoreSummary.lastProbeMessage = L10n.string(
        "substore.probe.empty_url",
        "Sub-Store remote URL is empty."
      )
      return
    }

    isBusy = true
    Task {
      defer { isBusy = false }
      do {
        var request = URLRequest(url: url)
        request.timeoutInterval = 10
        let (_, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse {
          subStoreSummary.lastProbeMessage = L10n.format(
            "substore.probe.http",
            "HTTP %d from %@",
            http.statusCode,
            url.host ?? remoteURL
          )
        } else {
          subStoreSummary.lastProbeMessage = L10n.format(
            "substore.probe.connected",
            "Connected to %@",
            url.host ?? remoteURL
          )
        }
      } catch {
        subStoreSummary.lastProbeMessage = error.localizedDescription
      }
    }
  }

  func importRemoteProfile() {
    let trimmedURL = resolvedRemoteProfileURL()

    guard !trimmedURL.isEmpty else {
      lastError = RemoteImportError.emptyURL.localizedDescription
      return
    }

    guard let url = URL(string: trimmedURL) else {
      lastError = RemoteImportError.invalidURL.localizedDescription
      return
    }

    guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
      lastError = RemoteImportError.unsupportedScheme.localizedDescription
      return
    }

    isBusy = true
    lastError = nil

    Task {
      defer { isBusy = false }

      do {
        var request = URLRequest(url: url)
        request.timeoutInterval = 20
        request.setValue("text/yaml,text/plain,application/yaml,*/*", forHTTPHeaderField: "Accept")

        let (data, response) = try await URLSession.shared.data(for: request)

        if let httpResponse = response as? HTTPURLResponse, !(200 ..< 300).contains(httpResponse.statusCode) {
          throw RemoteImportError.httpStatus(httpResponse.statusCode)
        }

        let payload = try Self.decodeRemoteProfilePayload(data)
        applyImportedText(
          payload,
          to: .profileYAML,
          remoteSource: trimmedURL,
          replaceRemoteSource: true,
          importReason: "Downloaded a remote profile from \(trimmedURL) and scheduled it for persistence."
        )
      } catch {
        lastError = error.localizedDescription
      }
    }
  }

  func pasteRemoteProfileURL(importImmediately: Bool = false) {
    let clipboardValue = UIPasteboard.general.string?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

    guard !clipboardValue.isEmpty else {
      lastError = L10n.string("profiles.remote.error.clipboard_empty", "Clipboard does not contain a subscription URL.")
      return
    }

    remoteProfileURL = clipboardValue
    lastError = nil

    if importImmediately {
      importRemoteProfile()
    }
  }

  func restoreDefaultRemoteProfileURL() {
    remoteProfileURL = Self.defaultRemoteProfileURL
    lastError = nil
  }

  func appendProtocolTemplate(_ preset: ProxyTemplatePreset) {
    applyImportedText(
      Self.mergeProxyTemplate(preset, into: profileYaml),
      to: .profileYAML,
      saveToProfileLibraryAfterPersist: false,
      importReason: "Appended the \(preset.title) template to the active profile and scheduled a persistence refresh."
    )
  }

  func importTextFile(from url: URL, kind: ImportedConfigKind) {
    let didAccess = url.startAccessingSecurityScopedResource()
    isBusy = true
    Task { [weak self] in
      guard let self else {
        if didAccess {
          url.stopAccessingSecurityScopedResource()
        }
        return
      }

      defer {
        if didAccess {
          url.stopAccessingSecurityScopedResource()
        }
        self.isBusy = false
      }

      do {
        let text = try await Self.readTextFile(at: url)
        self.applyImportedText(
          text,
          to: kind,
          remoteSource: nil,
          replaceRemoteSource: kind == .profileYAML,
          saveToProfileLibraryAfterPersist: kind == .profileYAML,
          importReason: "Imported a local \(kind.rawValue) file and scheduled it for persistence."
        )
      } catch {
        self.lastError = error.localizedDescription
      }
    }
  }

  private func refreshDerivedStateAsync() {
    let input = DerivedStateInput(
      profileYaml: self.profileYaml,
      controlledConfigYaml: self.controlledConfigYaml,
      appConfigJson: self.appConfigJson,
      overrideYaml: self.overrideYaml,
      overrideJavaScript: self.overrideJavaScript
    )
    if lastDerivedStateInput == input {
      return
    }
    lastDerivedStateInput = input

    let compatibilityService = self.compatibilityService

    proxyPreviewTask?.cancel()
    derivedStateTask?.cancel()
    proxyPreviewTask = Task.detached(priority: .userInitiated) {
      let proxyPreviewNodes = compatibilityService
        .extractProxyNames(from: input.profileYaml)
        .filter { $0 != "DIRECT" }
        .enumerated()
        .map { index, name in
          ProxyNodeRecord(
            id: "preview-\(index)-\(name)",
            name: name
          )
        }

      guard !Task.isCancelled else { return }

      await MainActor.run {
        guard !Task.isCancelled else { return }
        if self.proxyNodes != proxyPreviewNodes {
          self.proxyNodes = proxyPreviewNodes
        }
        self.refreshDisplayedProxyNodes()
        if self.proxyCount != proxyPreviewNodes.count {
          self.proxyCount = proxyPreviewNodes.count
        }
      }
    }

    derivedStateTask = Task.detached(priority: .utility) {
      let runtimeConfig = compatibilityService.buildRuntimeConfig(from: input.compatibilityInput)
      let routingPolicy = compatibilityService.effectiveRoutingPolicy(from: input.compatibilityInput)
      let proxyGroups = compatibilityService.extractProxyGroups(from: runtimeConfig)
      let dnsSummary = compatibilityService.parseDnsSummary(from: runtimeConfig)
      let tunSummary = compatibilityService.parseTunSummary(from: runtimeConfig)
      let mihomoSummary = compatibilityService.parseMihomoSummary(from: runtimeConfig)
      let subStoreSummary = compatibilityService.parseSubStoreSummary(from: input.appConfigJson)
      let proxyNodes = compatibilityService.extractProxyNodes(from: input.profileYaml)
      let rules = compatibilityService.extractRules(from: runtimeConfig)
      let resources = compatibilityService.extractResources(
        profileYaml: runtimeConfig,
        controlledConfigYaml: "",
        overrideYaml: ""
      )
      let hydratedResources = GeoResourceManager.hydrateStatuses(resources)

      guard !Task.isCancelled else { return }

      await MainActor.run {
        guard !Task.isCancelled else { return }
        self.effectiveRoutingPolicy = routingPolicy
        let didDNSContextChange =
          self.dnsSummary.enabled != dnsSummary.enabled
          || self.dnsSummary.enhancedMode != dnsSummary.enhancedMode
          || self.dnsSummary.fakeIPRange != dnsSummary.fakeIPRange
        self.dnsSummary = dnsSummary
        if didDNSContextChange {
          self.rebuildRouteExplanationsIfNeeded()
        }
        if self.proxyGroups != proxyGroups {
          self.setProxyGroups(proxyGroups)
        } else {
          self.refreshProxyPresentation()
        }
        self.refreshRuleInsightPresentation()
        self.tunSummary = tunSummary
        self.mihomoSummary = mihomoSummary
        self.subStoreSummary = subStoreSummary
        if self.proxyNodes != proxyNodes {
          self.proxyNodes = proxyNodes
        }
        self.refreshDisplayedProxyNodes()
        if self.rules != rules {
          self.rules = rules
        }
        if self.resources != hydratedResources {
          self.resources = hydratedResources
        }
        if self.ruleCount != rules.count {
          self.ruleCount = rules.count
        }
        if self.proxyCount != proxyNodes.count {
          self.proxyCount = proxyNodes.count
        }
      }
    }
  }

  @discardableResult
  private func syncSystemTunnelStatus(
    forceControllerSnapshotRefresh: Bool = false,
    scope: ConsoleRuntimeSnapshotScope = .full
  ) async -> ConsoleRuntimeSnapshot? {
    let persistedStatus = await runtimeIO.loadPersistedRuntimeStatus()
    let observation = await TunnelManager.shared.currentRuntimeObservation(fallback: persistedStatus)
    guard !Task.isCancelled else { return nil }

    let snapshot = await runtimeIO.loadRuntimeSnapshot(
      currentStatus: observation.runtimeStatus,
      extensionSnapshot: observation.extensionSnapshot,
      forceControllerSnapshotRefresh: forceControllerSnapshotRefresh,
      scope: scope
    )
    guard !Task.isCancelled else { return nil }

    applyRuntimeSnapshot(snapshot, currentStatus: observation.runtimeStatus)
    writeRuntimeDiagnosticsIfNeeded(
      status: observation.runtimeStatus,
      snapshot: snapshot
    )
    return snapshot
  }

  private func writeRuntimeDiagnosticsIfNeeded(
    status: RuntimeStatus,
    snapshot: ConsoleRuntimeSnapshot
  ) {
    let now = Date()
    let didRuntimeStatusChange = lastRuntimeDiagnosticsStatus != status
    let didExtensionSnapshotChange = lastRuntimeDiagnosticsExtensionSnapshot != snapshot.extensionSnapshot
    let didProxyGroupsChange = !snapshot.proxyGroups.isEmpty
      && lastRuntimeDiagnosticsProxyGroups != snapshot.proxyGroups
    let dataPlaneSnapshot = RuntimeDataPlaneSnapshot(
      traffic: snapshot.traffic,
      connections: snapshot.connections
    )
    let didDataPlaneChange = lastRuntimeDiagnosticsDataPlaneSnapshot != dataPlaneSnapshot
    let didRouteExplanationsChange = lastRuntimeDiagnosticsRouteExplanations != routeExplanations
    let routeExplanationMetrics = routeInsightDeriver.metrics
    let didRouteMetricsChange = lastRuntimeDiagnosticsRouteExplanationMetrics != routeExplanationMetrics
    let didThrottleWindowElapse = lastRuntimeDiagnosticsWriteAt.map {
      now.timeIntervalSince($0) >= Self.runtimeDiagnosticsWriteInterval
    } ?? true

    guard didRuntimeStatusChange
      || didExtensionSnapshotChange
      || didProxyGroupsChange
      || didDataPlaneChange
      || didRouteExplanationsChange
      || didRouteMetricsChange
      || didThrottleWindowElapse else {
      return
    }

    ConsoleDiagnosticsWriter.shared.writeRuntimeDiagnostics(
      status: status,
      snapshot: snapshot,
      routeExplanations: routeExplanations,
      routeExplanationMetrics: routeExplanationMetrics
    )
    lastRuntimeDiagnosticsWriteAt = now
    lastRuntimeDiagnosticsStatus = status
    lastRuntimeDiagnosticsExtensionSnapshot = snapshot.extensionSnapshot
    if !snapshot.proxyGroups.isEmpty {
      lastRuntimeDiagnosticsProxyGroups = snapshot.proxyGroups
    }
    lastRuntimeDiagnosticsDataPlaneSnapshot = dataPlaneSnapshot
    lastRuntimeDiagnosticsRouteExplanations = routeExplanations
    lastRuntimeDiagnosticsRouteExplanationMetrics = routeExplanationMetrics
  }

  private func processPendingProxySelectionIfNeeded() {
    guard let request = proxySelectionState.nextPendingRequest else { return }

    guard !shouldWaitForProxyProviderWarmup(beforeApplying: request) else {
      notePendingProxySelectionWaitingForProviderWarmup()
      return
    }

    guard controllerReadyForPendingProxySelections else {
      notePendingProxySelectionWaitingForController()
      return
    }

    guard let activeRequest = proxySelectionState.beginNextRequest() else { return }
    refreshProxyPresentation()

    Task { [weak self] in
      guard let self else { return }

      do {
        try await self.runtimeIO.selectProxy(group: activeRequest.groupName, proxy: activeRequest.proxy)
        self.handleProxySelectionSuccess(activeRequest)
      } catch {
        self.handleProxySelectionFailure(activeRequest, error: error)
      }
    }
  }

  private func handleProxySelectionSuccess(_ request: ProxySelectionRequest) {
    storeConfirmedSelection(request.proxy, for: request.groupName)
    updateLocalProxySelection(groupName: request.groupName, proxy: request.proxy)
    persistDisplayedProxyGroups()
    proxySelectionState.completeActiveRequest()
    refreshProxyPresentation()
    SharedStore.appendLog(
      level: "info",
      message: "Applied proxy selection '\(request.proxy)' for group '\(request.groupName)' through the embedded controller."
    )

    if !proxySelectionState.hasPending {
      refresh()
    } else {
      processPendingProxySelectionIfNeeded()
    }
  }

  private func handleProxySelectionFailure(_ request: ProxySelectionRequest, error: Error) {
    proxySelectionState.completeActiveRequest()
    refreshProxyPresentation()

    let hasNewerSelectionForGroup = proxySelectionState.hasNewerSelection(forGroup: request.groupName)
    if shouldRetryProxySelectionAfterProviderWarmup(for: request, error: error) {
      proxySelectionState.requeueIfNoNewerSelection(request)
      notePendingProxySelectionWaitingForProviderWarmup()
      refresh()
      return
    }

    if shouldRetryProxySelectionAfterControllerWarmup(for: request, error: error) {
      proxySelectionState.requeueIfNoNewerSelection(request)
      notePendingProxySelectionWaitingForController()
      refresh()
      return
    }

    lastError = error.localizedDescription
    proxySelectionState.clearWaitReason()
    refreshProxyPresentation()
    SharedStore.appendLog(
      level: "warning",
      message: "Failed to apply proxy selection '\(request.proxy)' for group '\(request.groupName)': \(error.localizedDescription)"
    )
    if !hasNewerSelectionForGroup {
      let fallbackSelection = runtimeConfirmedSelection(from: error) ?? confirmedSelection(for: request.groupName)
      storeConfirmedSelection(fallbackSelection, for: request.groupName, refreshPresentation: false)
      SharedStore.appendLog(
        level: "debug",
        message: "Kept preferred proxy selection '\(request.proxy)' for group '\(request.groupName)' after a failed apply so the user's intent can be retried against the next stable runtime snapshot."
      )
      updateLocalProxySelection(groupName: request.groupName, proxy: fallbackSelection)
      persistDisplayedProxyGroups()
    }

    if !proxySelectionState.hasPending {
      refresh()
    } else {
      processPendingProxySelectionIfNeeded()
    }
  }

  private func updateLocalProxySelection(groupName: String, proxy: String?) {
    guard var group = proxyGroupsByName[groupName] else { return }
    guard group.selected != proxy else { return }
    group.selected = proxy
    var updatedGroups = proxyGroups
    guard let index = updatedGroups.firstIndex(where: { $0.name == groupName }) else { return }
    updatedGroups[index] = group
    setProxyGroups(updatedGroups)
  }

  private func setProxyGroups(_ groups: [ProxyGroupSnapshot]) {
    let normalizedGroups = groups.map { $0.normalizedForDisplay() }
    guard proxyGroups != normalizedGroups else { return }

    let nextProxyGroupsByName = normalizedGroups.reduce(into: [String: ProxyGroupSnapshot]()) { result, group in
      result[group.name] = group
    }
    let nextDisplayedProxyGroups = Self.visibleProxyGroups(
      from: normalizedGroups,
      mode: runtimeStatus.mode
    )
    proxyGroups = normalizedGroups
    proxyGroupsByName = nextProxyGroupsByName
    proxyPresentationDeriver.invalidateSortCache()
    if displayedProxyGroups != nextDisplayedProxyGroups {
      displayedProxyGroups = nextDisplayedProxyGroups
    }
    refreshProxyPresentation()
  }

  private func refreshDisplayedProxyGroups() {
    let nextDisplayedProxyGroups = Self.visibleProxyGroups(
      from: proxyGroups,
      mode: runtimeStatus.mode
    )
    if displayedProxyGroups != nextDisplayedProxyGroups {
      displayedProxyGroups = nextDisplayedProxyGroups
    }
    refreshProxyPresentation()
  }

  private func refreshProxyPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingProxyPresentationRefresh = true
      return
    }
    updateProxyPresentationNow()
  }

  private func updateProxyPresentationNow() {
    proxyPresentation.update(
      proxyPresentationDeriver.makeState(proxyPresentationContext())
    )
  }

  private func proxyPresentationContext() -> ProxyPresentationContext {
    ProxyPresentationContext(
      runtimeStatus: runtimeStatus,
      displayedGroups: displayedProxyGroups,
      displayedNodes: displayedProxyNodes,
      totalProxyNodeCount: proxyNodes.count,
      sortMode: proxyNodeSortMode,
      delayStatuses: proxyDelayStatuses,
      speedTestingGroupNames: proxyDelayGroupsInFlight,
      isApplyingImportedWorkspace: isApplyingImportedWorkspace,
      activeSelection: proxySelectionState.active,
      pendingSelections: proxySelectionState.pending,
      confirmedSelections: proxySelectionState.confirmed,
      preferredSelections: proxySelectionState.preferred,
      runtimeCanAcceptProxySelectionSoon: runtimeCanAcceptProxySelectionSoon,
      pendingWaitReason: proxySelectionState.waitReason
    )
  }

  private static func visibleProxyGroups(
    from groups: [ProxyGroupSnapshot],
    mode: String
  ) -> [ProxyGroupSnapshot] {
    ProxyPresentationDeriver.visibleProxyGroups(from: groups, mode: mode)
  }

  private func setConnections(_ newConnections: [ConnectionSnapshot]) {
    if connections != newConnections {
      connections = newConnections
      refreshConnectionsPresentation()
    }
  }

  private func rebuildRouteExplanationsIfNeeded() {
    guard let derivation = routeInsightDeriver.rebuild(
      connections: connections,
      fakeDnsEnabled: runtimeStatus.fakeDnsEnabled,
      fakeIPRange: dnsSummary.fakeIPRange
    ) else { return }

    if routeExplanations != derivation.explanations {
      routeExplanations = derivation.explanations
    }
    ConsoleDiagnosticsWriter.shared.writeRouteExplanationsIfChanged(derivation.explanations)
    if proxiedRouteExplanationCount != derivation.proxiedCount {
      proxiedRouteExplanationCount = derivation.proxiedCount
    }
    if hiddenRouteExplanationCount != derivation.hiddenCount {
      hiddenRouteExplanationCount = derivation.hiddenCount
    }
    refreshRuleInsightPresentation()
  }

  private func noteEmptyRouteInsightSnapshotIfNeeded(_ snapshot: ConsoleRuntimeSnapshot) {
    guard snapshot.connections.isEmpty else { return }

    let controllerAddress = snapshot.extensionSnapshot.controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let controllerState = controllerAddress.isEmpty
      ? "no controller address"
      : "controller \(controllerAddress)"
    let runtimeState = snapshot.extensionSnapshot.runtimeStatus.state.rawValue
    SharedStore.appendLog(
      level: "debug",
      message: "Rule Insight refreshed an empty connection snapshot while runtime=\(runtimeState), vpnConnected=\(snapshot.extensionSnapshot.runtimeStatus.vpnConnected), running=\(snapshot.extensionSnapshot.running), \(controllerState)."
    )
  }

  private func refreshRuleInsightPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingRuleInsightPresentationRefresh = true
      return
    }
    updateRuleInsightPresentationNow()
  }

  private func updateRuleInsightPresentationNow() {
    ruleInsightPresentation.update(
      RuleInsightPresentationState(
        runtimeState: runtimeStatus.state,
        runtimeMode: runtimeStatus.mode,
        vpnConnected: runtimeStatus.vpnConnected,
        fakeDnsEnabled: runtimeStatus.fakeDnsEnabled,
        connectionCount: connections.count,
        usingRecentSnapshot: connections.isEmpty && !routeExplanations.isEmpty,
        controllerAddress: extensionSnapshot.controllerAddress,
        sharedStoreDiagnostics: sharedStoreDiagnostics,
        explanations: routeExplanations,
        proxiedCount: proxiedRouteExplanationCount,
        hiddenCount: hiddenRouteExplanationCount,
        metrics: routeInsightDeriver.metrics
      )
    )
  }

  private func applyRuntimeSnapshot(_ snapshot: ConsoleRuntimeSnapshot, currentStatus: RuntimeStatus) {
    performPresentationRefreshBatch {
      applyRuntimeSnapshotChanges(snapshot, currentStatus: currentStatus)
    }
  }

  private func performPresentationRefreshBatch(_ updates: () -> Void) {
    presentationRefreshBatchDepth += 1
    updates()
    presentationRefreshBatchDepth -= 1
    guard presentationRefreshBatchDepth == 0 else { return }

    let shouldRefreshProxyPresentation = pendingProxyPresentationRefresh
    let shouldRefreshRuleInsightPresentation = pendingRuleInsightPresentationRefresh
    let shouldRefreshShellPresentation = pendingShellPresentationRefresh
    let shouldRefreshOverviewPresentation = pendingOverviewPresentationRefresh
    let shouldRefreshConnectionsPresentation = pendingConnectionsPresentationRefresh
    let shouldRefreshLogsPresentation = pendingLogsPresentationRefresh
    let shouldRefreshRulesPresentation = pendingRulesPresentationRefresh
    let shouldRefreshDnsPresentation = pendingDnsPresentationRefresh
    let shouldRefreshResourcesPresentation = pendingResourcesPresentationRefresh
    let shouldRefreshCorePresentation = pendingCorePresentationRefresh
    let shouldRefreshSubStorePresentation = pendingSubStorePresentationRefresh
    let shouldRefreshSettingsPresentation = pendingSettingsPresentationRefresh
    let shouldRefreshProfilesPresentation = pendingProfilesPresentationRefresh
    let shouldRefreshOverridePresentation = pendingOverridePresentationRefresh
    pendingProxyPresentationRefresh = false
    pendingRuleInsightPresentationRefresh = false
    pendingShellPresentationRefresh = false
    pendingOverviewPresentationRefresh = false
    pendingConnectionsPresentationRefresh = false
    pendingLogsPresentationRefresh = false
    pendingRulesPresentationRefresh = false
    pendingDnsPresentationRefresh = false
    pendingResourcesPresentationRefresh = false
    pendingCorePresentationRefresh = false
    pendingSubStorePresentationRefresh = false
    pendingSettingsPresentationRefresh = false
    pendingProfilesPresentationRefresh = false
    pendingOverridePresentationRefresh = false

    if shouldRefreshProxyPresentation {
      updateProxyPresentationNow()
    }
    if shouldRefreshRuleInsightPresentation {
      updateRuleInsightPresentationNow()
    }
    if shouldRefreshShellPresentation {
      updateShellPresentationNow()
    }
    if shouldRefreshOverviewPresentation {
      updateOverviewPresentationNow()
    }
    if shouldRefreshConnectionsPresentation {
      updateConnectionsPresentationNow()
    }
    if shouldRefreshLogsPresentation {
      updateLogsPresentationNow()
    }
    if shouldRefreshRulesPresentation {
      updateRulesPresentationNow()
    }
    if shouldRefreshDnsPresentation {
      updateDnsPresentationNow()
    }
    if shouldRefreshResourcesPresentation {
      updateResourcesPresentationNow()
    }
    if shouldRefreshCorePresentation {
      updateCorePresentationNow()
    }
    if shouldRefreshSubStorePresentation {
      updateSubStorePresentationNow()
    }
    if shouldRefreshSettingsPresentation {
      updateSettingsPresentationNow()
    }
    if shouldRefreshProfilesPresentation {
      updateProfilesPresentationNow()
    }
    if shouldRefreshOverridePresentation {
      updateOverridePresentationNow()
    }
  }

  private func applyRuntimeSnapshotChanges(_ snapshot: ConsoleRuntimeSnapshot, currentStatus: RuntimeStatus) {
    let runtimeModeChanged = runtimeStatus.mode != currentStatus.mode
    let runtimeFakeDNSChanged = runtimeStatus.fakeDnsEnabled != currentStatus.fakeDnsEnabled
    var shouldRefreshRuleInsightPresentation = false
    if runtimeStatus != currentStatus {
      runtimeStatus = currentStatus
      shouldRefreshRuleInsightPresentation = true
      if runtimeModeChanged {
        refreshDisplayedProxyGroups()
      }
      if runtimeFakeDNSChanged {
        rebuildRouteExplanationsIfNeeded()
      }
    }
    synchronizeTunnelInteractionLock(with: currentStatus)
    if extensionSnapshot != snapshot.extensionSnapshot {
      extensionSnapshot = snapshot.extensionSnapshot
      shouldRefreshRuleInsightPresentation = true
    }

    let deferAutomaticProxyPreferenceReconciliation = proxyProviderWarmupStillInFlightForPendingProxySelections
    let runtimeProxyGroupsBelongToCurrentWorkspace = currentWorkspaceCanAcceptRuntimeProxyGroups
    let hasAuthoritativeProxyGroups =
      runtimeProxyGroupsBelongToCurrentWorkspace && !snapshot.proxyGroups.isEmpty
    let canReconcileProxyPreferences =
      hasAuthoritativeProxyGroups && snapshot.extensionSnapshot.canAuthoritativelyReconcileProxyPreferences

    if canReconcileProxyPreferences {
      if !proxySelectionState.inFlight, !proxySelectionState.hasPending {
        syncConfirmedSelections(from: snapshot.proxyGroups)
      }
      if !deferAutomaticProxyPreferenceReconciliation {
        syncPreferredSelections(from: snapshot.proxyGroups)
        persistPreferredProxySelectionsIfNeeded(using: snapshot.proxyGroups)
      }
    } else if !proxySelectionState.preferred.isEmpty,
              runtimeStatus.state == .starting || extensionSnapshot.startupAcceptedForAppOperations {
      SharedStore.appendLog(
        level: "debug",
        message: "Skipped proxy preference reconciliation because the latest runtime snapshot is not authoritative during tunnel startup."
      )
    }

    if runtimeProxyGroupsBelongToCurrentWorkspace, !snapshot.proxyGroups.isEmpty {
      let updatedProxyGroups = mergeProxyGroupsPreservingSelections(snapshot.proxyGroups)
      if proxyGroups != updatedProxyGroups {
        setProxyGroups(updatedProxyGroups)
      }
    } else if !runtimeProxyGroupsBelongToCurrentWorkspace, !snapshot.proxyGroups.isEmpty {
      SharedStore.appendLog(
        level: "debug",
        message: "Ignored stale runtime proxy groups because the editor workspace has changed and has not been persisted successfully yet."
      )
    }
    if let snapshotLogs = snapshot.logs, logs != snapshotLogs {
      logs = snapshotLogs
    }
    if traffic != snapshot.traffic {
      traffic = snapshot.traffic
    }
    let connectionsChanged = connections != snapshot.connections
    if connections != snapshot.connections {
      setConnections(snapshot.connections)
    }
    if runtimeProxyGroupsBelongToCurrentWorkspace {
      if !snapshot.routeExplanations.isEmpty {
        applyRouteExplanationsFromRuntime(snapshot.routeExplanations)
      } else if connectionsChanged || runtimeFakeDNSChanged {
        rebuildRouteExplanationsIfNeeded()
      }
    } else if !routeExplanations.isEmpty || proxiedRouteExplanationCount != 0 || hiddenRouteExplanationCount != 0 {
      clearRouteExplanationsForWorkspaceSwitch()
    }
    if let snapshotSavedProfiles = snapshot.savedProfiles, savedProfiles != snapshotSavedProfiles {
      savedProfiles = snapshotSavedProfiles
    }
    if let snapshotBackups = snapshot.backups, backups != snapshotBackups {
      backups = snapshotBackups
    }
    if let snapshotVersion = snapshot.version, version != snapshotVersion {
      version = snapshotVersion
    }
    refreshProxyPresentation()
    if shouldRefreshRuleInsightPresentation {
      refreshRuleInsightPresentation()
    }

    switch currentStatus.state {
    case .running:
      setBusy(false)
      setActivityMessage(nil)
    case .failed:
      setBusy(false)
      lastError = currentStatus.lastFailureReason ?? L10n.string(
        "error.tunnel.start_failed_without_detail",
        "The tunnel did not enter the running state. Check the VPN prompt, system VPN settings, and Packet Tunnel logs."
      )
      setActivityMessage(nil)
    case .starting:
      setActivityMessage(!currentStatus.startupMessage.isEmpty
        ? currentStatus.startupMessage
        : L10n.string(
          "tunnel.activity.waiting",
          "Tunnel start request sent. Waiting for iOS VPN status to change."
        )
      )
      setBusy(true)
    case .stopping:
      setBusy(true)
      if activityMessage == nil {
        setActivityMessage(L10n.string("tunnel.activity.stopping", "Stopping Packet Tunnel and releasing runtime resources."))
      }
    case .idle, .stopped:
      if activityMessage == L10n.string(
        "tunnel.activity.waiting",
        "Tunnel start request sent. Waiting for iOS VPN status to change."
      ) || activityMessage == L10n.string(
        "tunnel.activity.stopping",
        "Stopping Packet Tunnel and releasing runtime resources."
      ) {
        setActivityMessage(nil)
      }
      setBusy(false)
    }

    if let failure = currentStatus.lastFailureReason, !failure.isEmpty {
      lastError = failure
    }

    if hasAuthoritativeProxyGroups, !deferAutomaticProxyPreferenceReconciliation {
      enqueuePreferredProxySelectionsIfNeeded(using: snapshot.proxyGroups)
    }

    if currentStatus.isTerminalTunnelState {
      if currentStatus.state == .running {
        if proxySelectionState.canBeginNextRequest {
          processPendingProxySelectionIfNeeded()
        }
      } else {
        clearPendingProxySelections()
      }
    } else if proxySelectionState.canBeginNextRequest {
      processPendingProxySelectionIfNeeded()
    }
  }

  private func applyRouteExplanationsFromRuntime(_ explanations: [RouteExplanation]) {
    routeInsightDeriver.seed(explanations)
    if routeExplanations != explanations {
      routeExplanations = explanations
    }
    ConsoleDiagnosticsWriter.shared.writeRouteExplanationsIfChanged(explanations)
    let proxiedCount = RouteExplanationResolver.proxiedCount(in: explanations)
    if proxiedRouteExplanationCount != proxiedCount {
      proxiedRouteExplanationCount = proxiedCount
    }
    if hiddenRouteExplanationCount != 0 {
      hiddenRouteExplanationCount = 0
    }
    refreshRuleInsightPresentation()
  }

  private func clearRouteExplanationsForWorkspaceSwitch() {
    routeInsightDeriver = RouteInsightDeriver(limit: Self.routeExplanationConnectionLimit)
    if routeExplanations != [] {
      routeExplanations = []
    }
    if proxiedRouteExplanationCount != 0 {
      proxiedRouteExplanationCount = 0
    }
    if hiddenRouteExplanationCount != 0 {
      hiddenRouteExplanationCount = 0
    }
    refreshRuleInsightPresentation()
  }

  private func setTunnelInteractionLock(_ lock: TunnelInteractionLock?) {
    tunnelInteractionLock = lock
    let nextValue = lock != nil
    if isTunnelInteractionLocked != nextValue {
      isTunnelInteractionLocked = nextValue
    }
  }

  private func setBusy(_ nextValue: Bool) {
    if isBusy != nextValue {
      isBusy = nextValue
    }
  }

  private func setActivityMessage(_ nextValue: String?) {
    if activityMessage != nextValue {
      activityMessage = nextValue
    }
  }

  private func refreshShellPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingShellPresentationRefresh = true
      return
    }
    updateShellPresentationNow()
  }

  private func updateShellPresentationNow() {
    shellPresentation.update(
      ShellPresentationState(
        activityMessage: activityMessage,
        isShowingActivity: (isBusy || isTunnelInteractionLocked) && activityMessage != nil
      )
    )
  }

  private func refreshOverviewPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingOverviewPresentationRefresh = true
      return
    }
    updateOverviewPresentationNow()
  }

  private func updateOverviewPresentationNow() {
    let startupMessage = !extensionSnapshot.startupMessage.isEmpty
      ? extensionSnapshot.startupMessage
      : runtimeStatus.startupMessage
    let startupStateShowsMessage: Bool
    switch runtimeStatus.state {
    case .starting, .stopping, .failed:
      startupStateShowsMessage = true
    case .idle, .running, .stopped:
      startupStateShowsMessage = false
    }

    let lastFailureReason = extensionSnapshot.lastFailureReason ?? runtimeStatus.lastFailureReason
    let lastFailurePhase = extensionSnapshot.lastFailurePhase ?? runtimeStatus.lastFailurePhase
    let lastStopReason = extensionSnapshot.lastStopReason ?? runtimeStatus.lastStopReason
    let phase = !extensionSnapshot.startupPhase.isEmpty
      ? extensionSnapshot.startupPhase
      : runtimeStatus.startupPhase
    let activeProxySummary = ProxySummaryResolver.activeProxySummary(
      proxyGroups: proxyGroups,
      connections: connections
    ) ?? L10n.string("common.none", "None")
    let hasWorkspace = hasCurrentProfileWorkspace
    let profileSummary = hasWorkspace
      ? currentProfileDisplayName
      : L10n.string("overview.connect.no_profile", "No imported subscription yet")

    overviewPresentation.update(
      OverviewPresentationState(
        runtimeState: runtimeStatus.state,
        runtimeMode: runtimeStatus.mode,
        fakeDnsEnabled: runtimeStatus.fakeDnsEnabled,
        vpnConnected: runtimeStatus.vpnConnected || extensionSnapshot.runtimeStatus.vpnConnected,
        dataPlaneReady: runtimeStatus.dataPlaneReady || extensionSnapshot.runtimeStatus.dataPlaneReady,
        hasProxyNodes: !proxyNodes.isEmpty,
        tunnelControlsDisabled: tunnelControlsDisabled,
        activeProxySummary: activeProxySummary,
        currentProfileSummary: profileSummary,
        runtimePhaseSummary: phase.isEmpty ? L10n.string("runtime.phase.idle", "Runtime is idle.") : phase,
        planStartupMessage: startupStateShowsMessage ? startupMessage : "",
        diagnosticStartupMessage: startupStateShowsMessage ? startupMessage : "",
        lastFailureReason: lastFailureReason,
        lastFailurePhase: lastFailurePhase,
        lastStopReason: lastStopReason,
        lastError: lastError,
        lastRemoteImportSource: lastRemoteImportSource,
        trafficSummary: Self.trafficSummary(from: traffic)
      )
    )
  }

  private func refreshConnectionsPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingConnectionsPresentationRefresh = true
      return
    }
    updateConnectionsPresentationNow()
  }

  private func updateConnectionsPresentationNow() {
    connectionsPresentation.update(
      ConnectionsPresentationState(connections: connections)
    )
  }

  private func refreshLogsPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingLogsPresentationRefresh = true
      return
    }
    updateLogsPresentationNow()
  }

  private func updateLogsPresentationNow() {
    let displayedLogs = logs.suffix(Self.logPreviewLimit).map { log in
      LogPresentationRecord(
        id: log.id,
        timestamp: Self.logTimestampFormatter.string(from: log.timestamp),
        level: log.level,
        message: log.message
      )
    }
    logsPresentation.update(
      LogsPresentationState(records: displayedLogs, totalCount: logs.count)
    )
  }

  private func refreshRulesPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingRulesPresentationRefresh = true
      return
    }
    updateRulesPresentationNow()
  }

  private func updateRulesPresentationNow() {
    let records = rules.prefix(Self.rulePreviewLimit).enumerated().map { index, rule in
      RulePresentationRecord(id: "\(index):\(rule.id)", rule: rule)
    }
    rulesPresentation.update(
      RulesPresentationState(records: records, totalCount: ruleCount)
    )
  }

  private func refreshDnsPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingDnsPresentationRefresh = true
      return
    }
    updateDnsPresentationNow()
  }

  private func updateDnsPresentationNow() {
    dnsPresentation.update(
      DnsPresentationState(
        summary: dnsSummary,
        controlledConfigYaml: controlledConfigYaml
      )
    )
  }

  private func refreshResourcesPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingResourcesPresentationRefresh = true
      return
    }
    updateResourcesPresentationNow()
  }

  private func updateResourcesPresentationNow() {
    resourcesPresentation.update(
      ResourcesPresentationState(resources: resources)
    )
  }

  private func refreshCorePresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingCorePresentationRefresh = true
      return
    }
    updateCorePresentationNow()
  }

  private func updateCorePresentationNow() {
    corePresentation.update(
      CorePresentationState(
        mihomoSummary: mihomoSummary,
        tunSummary: tunSummary
      )
    )
  }

  private func refreshSubStorePresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingSubStorePresentationRefresh = true
      return
    }
    updateSubStorePresentationNow()
  }

  private func updateSubStorePresentationNow() {
    subStorePresentation.update(
      SubStorePresentationState(
        summary: subStoreSummary,
        isBusy: isBusy
      )
    )
  }

  private func refreshSettingsPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingSettingsPresentationRefresh = true
      return
    }
    updateSettingsPresentationNow()
  }

  private func updateSettingsPresentationNow() {
    settingsPresentation.update(
      SettingsPresentationState(
        preservedButInactiveFields: validationReport.preservedButInactiveFields,
        exportBundleName: exportBundleName,
        lastExportPath: lastExportPath,
        appConfigJson: appConfigJson
      )
    )
  }

  private func refreshProfilesPresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingProfilesPresentationRefresh = true
      return
    }
    updateProfilesPresentationNow()
  }

  private func updateProfilesPresentationNow() {
    profilesPresentation.update(
      ProfilesPresentationState(
        currentProfileDisplayName: currentProfileDisplayName,
        savedProfiles: savedProfiles,
        lastExportPath: lastExportPath,
        lastRemoteImportSource: lastRemoteImportSource,
        draftProfileName: draftProfileName,
        remoteProfileURL: remoteProfileURL,
        isBusy: isBusy,
        shouldCollapseProfileEditor: shouldCollapseProfileEditor,
        isLargeProfile: isLargeProfile,
        profileByteCount: profileByteCount,
        proxyCount: proxyCount,
        ruleCount: ruleCount,
        profileYaml: profileYaml,
        controlledConfigYaml: controlledConfigYaml,
        draftBackupName: draftBackupName,
        backups: backups
      )
    )
  }

  private func refreshOverridePresentation() {
    guard presentationRefreshBatchDepth == 0 else {
      pendingOverridePresentationRefresh = true
      return
    }
    updateOverridePresentationNow()
  }

  private func updateOverridePresentationNow() {
    overridePresentation.update(
      OverridePresentationState(
        overrideYaml: overrideYaml,
        overrideJavaScript: overrideJavaScript
      )
    )
  }

  private static func trafficSummary(from traffic: TrafficSnapshot) -> String {
    L10n.format(
      "overview.metrics.traffic_summary",
      "%@ down · %@ up",
      DisplayValue.bytes(traffic.downBytes),
      DisplayValue.bytes(traffic.upBytes)
    )
  }

  private func synchronizeTunnelInteractionLock(with currentStatus: RuntimeStatus) {
    switch currentStatus.state {
    case .starting:
      setTunnelInteractionLock(.starting)
    case .stopping:
      setTunnelInteractionLock(.stopping)
    case .running:
      if tunnelInteractionLock == .starting {
        setTunnelInteractionLock(nil)
      }
    case .idle, .stopped, .failed:
      setTunnelInteractionLock(nil)
    }
  }

  private var controllerReadyForPendingProxySelections: Bool {
    let metadata = SharedStore.readControllerMetadata()
    if metadata.active {
      return true
    }

    let startupAccepted = runtimeStatus.startupAcceptedForControllerWarmup
      || extensionSnapshot.startupAcceptedForAppOperations

    let pendingListenAddress = metadata.listenAddress
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if startupAccepted, !pendingListenAddress.isEmpty {
      return true
    }

    let pendingBaseURL = metadata.baseURLString
      .trimmingCharacters(in: .whitespacesAndNewlines)
    if startupAccepted, !pendingBaseURL.isEmpty {
      return true
    }

    let publishedControllerAddress = extensionSnapshot.controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let liveTunnelContext = extensionSnapshot.running || runtimeStatus.liveTunnelContext
    return liveTunnelContext && !publishedControllerAddress.isEmpty
  }

  private var runtimeCanAcceptProxySelectionSoon: Bool {
    runtimeStatus.liveTunnelContext
      || extensionSnapshot.running
      || runtimeStatus.startupAcceptedForControllerWarmup
      || extensionSnapshot.startupAcceptedForAppOperations
  }

  private var controllerWarmupStillInFlightForPendingProxySelections: Bool {
    guard runtimeStatus.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true else {
      return false
    }

    let livePhase = extensionSnapshot.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    if livePhase == "warmingProviders" {
      return true
    }

    let persistedPhase = runtimeStatus.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    if persistedPhase == "warmingProviders" {
      return true
    }

    return runtimeStatus.state == .starting
      || runtimeStatus.startupAcceptedForControllerWarmup
      || extensionSnapshot.startupAcceptedForAppOperations
  }

  private var proxyProviderWarmupStillInFlightForPendingProxySelections: Bool {
    guard runtimeStatus.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true else {
      return false
    }

    let livePhase = extensionSnapshot.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    if livePhase == "warmingProviders" {
      return true
    }

    let persistedPhase = runtimeStatus.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    return persistedPhase == "warmingProviders"
  }

  private func notePendingProxySelectionWaitingForController() {
    guard proxySelectionState.waitFor(.controllerWarmup) else { return }
    refreshProxyPresentation()
    SharedStore.appendLog(
      level: "info",
      message: "Queued the proxy selection until the embedded controller publishes or warms up its local endpoint."
    )
  }

  private func notePendingProxySelectionWaitingForProviderWarmup() {
    guard proxySelectionState.waitFor(.providerWarmup) else { return }
    refreshProxyPresentation()
    SharedStore.appendLog(
      level: "info",
      message: "Queued the proxy selection until the requested proxy group finishes loading its provider-backed options."
    )
  }

  private func shouldWaitForProxyProviderWarmup(beforeApplying request: ProxySelectionRequest) -> Bool {
    guard proxyProviderWarmupStillInFlightForPendingProxySelections else {
      return false
    }

    return !currentSnapshotContainsProxySelectionTarget(request)
  }

  private func shouldRetryProxySelectionAfterControllerWarmup(
    for request: ProxySelectionRequest,
    error: Error
  ) -> Bool {
    guard isControllerUnavailable(error) else { return false }
    guard controllerWarmupStillInFlightForPendingProxySelections else {
      return false
    }

    return !proxySelectionState.hasNewerSelection(forGroup: request.groupName)
  }

  private func shouldRetryProxySelectionAfterProviderWarmup(
    for request: ProxySelectionRequest,
    error: Error
  ) -> Bool {
    guard isTransientProxySelectionAvailabilityError(error) else { return false }
    guard proxyProviderWarmupStillInFlightForPendingProxySelections else {
      return false
    }

    return !proxySelectionState.hasNewerSelection(forGroup: request.groupName)
  }

  private func isControllerUnavailable(_ error: Error) -> Bool {
    if let runtimeError = error as? MihomoRuntimeBridgeError,
       case .controllerUnavailable = runtimeError {
      return true
    }
    if let controllerError = error as? MihomoControllerClientError {
      switch controllerError {
      case .invalidMetadata, .timeout:
        return true
      case .httpError:
        break
      case .invalidResponse:
        break
      }
    }
    if let urlError = error as? URLError {
      switch urlError.code {
      case .cannotConnectToHost, .networkConnectionLost, .timedOut, .notConnectedToInternet:
        return true
      default:
        break
      }
    }
    let normalizedDescription = error.localizedDescription.lowercased()
    if normalizedDescription.contains("无法连接服务器")
      || normalizedDescription.contains("无法连接到服务器")
      || normalizedDescription.contains("could not connect to the server")
      || normalizedDescription.contains("cannot connect to host") {
      return true
    }
    return error.localizedDescription == MihomoRuntimeBridgeError.controllerUnavailable.localizedDescription
  }

  private func isTransientProxySelectionAvailabilityError(_ error: Error) -> Bool {
    if let controllerError = error as? MihomoControllerClientError {
      switch controllerError {
      case .httpError(let status, let body):
        let normalizedBody = body.lowercased()
        if status == 404 {
          return true
        }
        if status == 400,
           normalizedBody.contains("selector update error") {
          return true
        }
      default:
        break
      }
    }

    let normalizedDescription = error.localizedDescription.lowercased()
    return normalizedDescription.contains("selector update error")
      || normalizedDescription.contains("resource not found")
  }

  private func currentSnapshotContainsProxySelectionTarget(_ request: ProxySelectionRequest) -> Bool {
    guard let group = proxyGroupsByName[request.groupName] else { return false }
    return ProxySelectionCoordinator.isSelection(request.proxy, validFor: group)
  }

  private func runtimeConfirmedSelection(from error: Error) -> String? {
    guard let runtimeError = error as? RuntimeBridgeError,
          case .proxySelectionNotConfirmed(_, _, let actual) = runtimeError else {
      return nil
    }

    let normalizedSelection = actual?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return normalizedSelection.isEmpty ? nil : normalizedSelection
  }

  private func clearPendingProxySelections() {
    proxySelectionState.clearPendingRuntimeState()
    refreshProxyPresentation()
  }

  private func mergeProxyGroupsPreservingSelections(_ groups: [ProxyGroupSnapshot]) -> [ProxyGroupSnapshot] {
    groups
  }

  private func syncConfirmedSelections(from groups: [ProxyGroupSnapshot]) {
    for group in groups {
      storeConfirmedSelection(group.selected, for: group.name, refreshPresentation: false)
    }
    refreshProxyPresentation()
  }

  private func syncPreferredSelections(from groups: [ProxyGroupSnapshot]) {
    guard proxySelectionPreferenceSnapshotCanInvalidateStoredSelections(
      proxySelectionState.preferred,
      groups: groups
    ) else {
      SharedStore.appendLog(
        level: "debug",
        message: "Kept in-memory proxy selection preferences because the latest runtime proxy snapshot is not stable enough to prove those selections are invalid."
      )
      refreshProxyPresentation()
      return
    }

    proxySelectionState.materializePreferredSelections(within: groups)
    refreshProxyPresentation()
  }

  private func confirmedSelection(for groupName: String) -> String? {
    proxySelectionState.confirmedSelection(for: groupName)
  }

  private func storeConfirmedSelection(
    _ selection: String?,
    for groupName: String,
    refreshPresentation: Bool = true
  ) {
    proxySelectionState.storeConfirmedSelection(selection, for: groupName)
    if refreshPresentation {
      refreshProxyPresentation()
    }
  }

  private func preferredSelection(for groupName: String) -> String? {
    proxySelectionState.preferredSelection(for: groupName)
  }

  private func storePreferredSelection(
    _ selection: String?,
    for groupName: String,
    persist: Bool = true
  ) {
    guard proxySelectionState.storePreferredSelection(selection, for: groupName) else { return }

    if persist {
      persistPreferredProxySelections()
    }
    refreshProxyPresentation()
  }

  private func persistPreferredProxySelections() {
    do {
      try SharedStore.writeProxySelectionPreferences(materializedProxySelectionPreferences())
    } catch {
      lastError = error.localizedDescription
    }
  }

  private func persistPreferredProxySelectionsIfNeeded(using groups: [ProxyGroupSnapshot]) {
    guard extensionSnapshot.canAuthoritativelyReconcileProxyPreferences else { return }
    guard !groups.isEmpty else { return }

    let materializedSelections = materializedProxySelectionPreferences(within: groups)
    let storedSelections = SharedStore.readProxySelectionPreferences()
    guard storedSelections != materializedSelections else { return }

    let canInvalidateStoredSelections = proxySelectionPreferenceSnapshotCanInvalidateStoredSelections(
      storedSelections,
      groups: groups
    )
    if !canInvalidateStoredSelections && materializedSelections.isEmpty {
      SharedStore.appendLog(
        level: "debug",
        message: "Deferred clearing persisted proxy selection preferences because the latest runtime proxy snapshot is not stable enough to prove those selections are invalid."
      )
      return
    }

    do {
      try SharedStore.writeProxySelectionPreferences(materializedSelections)
      let message: String
      if materializedSelections.isEmpty {
        message = "Cleared persisted proxy selection preferences that no longer match the latest runtime snapshot."
      } else {
        message = "Persisted \(materializedSelections.count) explicit proxy selection preference(s) after validating them against the latest runtime snapshot."
      }
      SharedStore.appendLog(level: "debug", message: message)
    } catch {
      lastError = error.localizedDescription
    }
  }

  private func proxySelectionPreferenceSnapshotCanInvalidateStoredSelections(
    _ storedSelections: [String: String],
    groups: [ProxyGroupSnapshot]
  ) -> Bool {
    guard !storedSelections.isEmpty else {
      return true
    }

    guard !proxyProviderWarmupStillInFlightForPendingProxySelections else {
      return false
    }

    guard runtimeStatus.state == .stopped
      || runtimeStatus.state == .idle
      || runtimeStatus.state == .failed
      || snapshotHasSettledForProxyPreferenceReconciliation else {
      return false
    }

    let groupsByName = groups.reduce(into: [String: ProxyGroupSnapshot]()) { result, group in
      result[group.name] = group
    }
    for groupName in storedSelections.keys {
      guard let group = groupsByName[groupName], group.supportsManualSelection else {
        return false
      }
      let hasLoadedOptions = !group.displayOptions.isEmpty || !group.all.isEmpty
      if !hasLoadedOptions {
        return false
      }
    }

    return true
  }

  private var snapshotHasSettledForProxyPreferenceReconciliation: Bool {
    let phase = extensionSnapshot.startupPhase.trimmingCharacters(in: .whitespacesAndNewlines)
    guard extensionSnapshot.running || runtimeStatus.state == .running else {
      return false
    }
    guard phase == "running" || phase == "idle" || phase.isEmpty else {
      return false
    }
    return runtimeStatus.dataPlaneReady || extensionSnapshot.runtimeStatus.dataPlaneReady
  }

  private func persistDisplayedProxyGroups() {
    do {
      try SharedStore.writeProxyGroups(proxyGroups)
    } catch {
      lastError = error.localizedDescription
    }
  }

  private func enqueuePreferredProxySelectionsIfNeeded(using groups: [ProxyGroupSnapshot]) {
    guard runtimeCanAcceptProxySelectionSoon else { return }

    var enqueued = false
    for group in groups {
      guard group.supportsManualSelection,
            let preferred = effectivePreferredSelection(for: group, within: groups),
            !preferred.isEmpty,
            preferred != group.selected,
            ProxySelectionCoordinator.isSelection(preferred, validFor: group) else {
        continue
      }

      let request = ProxySelectionRequest(groupName: group.name, proxy: preferred)
      if proxySelectionState.contains(request) {
        continue
      }

      proxySelectionState.queue(request)
      enqueued = true
    }

    if enqueued {
      processPendingProxySelectionIfNeeded()
    }
  }

  private func currentInput() -> CompatibilityInput {
    CompatibilityInput(
      profileYaml: profileYaml,
      controlledConfigYaml: controlledConfigYaml,
      appConfigJson: appConfigJson,
      overrideYaml: overrideYaml,
      overrideJavaScript: overrideJavaScript
    )
  }

  private var currentWorkspaceCanAcceptRuntimeProxyGroups: Bool {
    lastPublishedInput == currentInput()
  }

  private func preferredRemoteProfileName() -> String? {
    let trimmedName = draftProfileName.trimmingCharacters(in: .whitespacesAndNewlines)
    let defaultName = L10n.string("profiles.default_name", "Default Profile")
    guard !trimmedName.isEmpty, trimmedName != defaultName else {
      return nil
    }
    return trimmedName
  }

  private func restoreActiveProfileIdentityIfPossible(for input: CompatibilityInput) {
    Task { [weak self] in
      guard let self,
            let profile = await profileLibraryCoordinator.findProfile(matching: input) else {
        return
      }
      activeProfileRecordID = profile.id
      draftProfileName = profile.name
      lastRemoteImportSource = profile.remoteSource
      if let remoteSource = profile.remoteSource,
         !remoteSource.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        remoteProfileURL = remoteSource
      }
    }
  }

  private func upsertRemoteImportedProfile(remoteSource: String) async throws -> ProfileBundleRecord {
    let record = try await profileLibraryCoordinator.upsertRemoteImportedProfile(
      remoteSource: remoteSource,
      input: currentInput(),
      fallbackName: preferredRemoteProfileName()
    )
    activeProfileRecordID = record.id
    return record
  }

  private func apply(
    _ input: CompatibilityInput,
    resetPreferredProxySelections: Bool = true,
    clearPersistedProxyGroups: Bool = true
  ) {
    resetProxySelectionStateForImportedWorkspace(
      resetPreferredProxySelections: resetPreferredProxySelections,
      clearPersistedProxyGroups: clearPersistedProxyGroups
    )
    lastDerivedStateInput = nil
    let input = compatibilityService.sanitizedMobileInput(input)
    profileYaml = input.profileYaml
    controlledConfigYaml = input.controlledConfigYaml
    appConfigJson = input.appConfigJson
    overrideYaml = input.overrideYaml
    overrideJavaScript = input.overrideJavaScript
    resetProfileEditorExpansionIfNeeded(for: input.profileYaml)
    applyWorkspaceDerivedStateSynchronously(for: input)
  }

  private func applyWorkspaceDerivedStateSynchronously(for input: CompatibilityInput) {
    let derivedInput = DerivedStateInput(input)
    effectiveRoutingPolicy = compatibilityService.effectiveRoutingPolicy(from: input)
    let runtimeConfig = compatibilityService.buildRuntimeConfig(from: input)
    let proxyGroups = compatibilityService.extractProxyGroups(from: runtimeConfig)
    let dnsSummary = compatibilityService.parseDnsSummary(from: runtimeConfig)
    let tunSummary = compatibilityService.parseTunSummary(from: runtimeConfig)
    let mihomoSummary = compatibilityService.parseMihomoSummary(from: runtimeConfig)
    let subStoreSummary = compatibilityService.parseSubStoreSummary(from: input.appConfigJson)
    let proxyNodes = compatibilityService.extractProxyNodes(from: input.profileYaml)
    let rules = compatibilityService.extractRules(from: runtimeConfig)
    let resources = GeoResourceManager.hydrateStatuses(
      compatibilityService.extractResources(
        profileYaml: runtimeConfig,
        controlledConfigYaml: "",
        overrideYaml: ""
      )
    )

    lastDerivedStateInput = derivedInput
    let didDNSContextChange =
      self.dnsSummary.enabled != dnsSummary.enabled
      || self.dnsSummary.enhancedMode != dnsSummary.enhancedMode
      || self.dnsSummary.fakeIPRange != dnsSummary.fakeIPRange
    self.dnsSummary = dnsSummary
    if didDNSContextChange {
      rebuildRouteExplanationsIfNeeded()
    }
    self.tunSummary = tunSummary
    self.mihomoSummary = mihomoSummary
    self.subStoreSummary = subStoreSummary
    setProxyGroups(proxyGroups)
    if self.proxyNodes != proxyNodes {
      self.proxyNodes = proxyNodes
    }
    refreshDisplayedProxyNodes()
    if self.rules != rules {
      self.rules = rules
    }
    if self.resources != resources {
      self.resources = resources
    }
    if proxyCount != proxyNodes.count {
      proxyCount = proxyNodes.count
    }
    if ruleCount != rules.count {
      ruleCount = rules.count
    }
  }

  private func applyImportedText(
    _ text: String,
    to kind: ImportedConfigKind,
    remoteSource: String? = nil,
    replaceRemoteSource: Bool = false,
    saveToProfileLibraryAfterPersist: Bool = false,
    importReason: String? = nil
  ) {
    if kind == .routingSnapshot {
      do {
        desktopRoutingSnapshot = try RoutingPolicyService.importDesktopSnapshot(Data(text.utf8))
        try applyRoutingPolicy(.desktopSnapshot)
        routingUpdateMessage = L10n.string("routing.snapshot_imported", "Rules imported and applied using the current proxy nodes.")
      } catch { lastError = error.localizedDescription }
      return
    }
    activeProfileRecordID = nil
    lastPublishedInput = nil
    resetProxySelectionStateForImportedWorkspace()
    lastDerivedStateInput = nil

    switch kind {
    case .profileYAML:
      profileYaml = text
      resetProfileEditorExpansionIfNeeded(for: text)
      if replaceRemoteSource {
        lastRemoteImportSource = remoteSource
      }
    case .controlledYAML:
      controlledConfigYaml = text
    case .appConfigJSON:
      appConfigJson = text
    case .overrideYAML:
      overrideYaml = text
    case .routingSnapshot:
      return
    }

    applyWorkspaceDerivedStateSynchronously(for: currentInput())
    validateOnly()
    schedulePersistImportedWorkspace(
      saveToProfileLibraryAfterPersist: saveToProfileLibraryAfterPersist,
      reason: importReason
        ?? "Imported \(kind.rawValue) into the active workspace and scheduled a persistence refresh."
    )
  }

  @discardableResult
  private func persistCurrentInput(
    showBusy: Bool,
    refreshRuntimeSnapshot: Bool
  ) async -> CompatibilityValidationReport? {
    if showBusy {
      isBusy = true
    }

    let input = compatibilityService.sanitizedMobileInput(currentInput())
    if input != currentInput() { apply(input, resetPreferredProxySelections: false, clearPersistedProxyGroups: false) }
    let compatibilityService = self.compatibilityService

    defer {
      if showBusy {
        isBusy = false
      }
    }

    do {
      let report = try await Task.detached(priority: .userInitiated) {
        try compatibilityService.persist(input)
      }.value
      validationReport = report
      lastError = report.isValid ? nil : report.blockingErrors.joined(separator: "\n")
      if report.isValid {
        lastPublishedInput = input
        warmupGeoResourcesIfNeeded(reason: "persist")
      }
      if refreshRuntimeSnapshot {
        refresh(refreshDerivedState: false)
      }
      return report
    } catch {
      lastError = error.localizedDescription
      return nil
    }
  }

  private func schedulePersistImportedWorkspace(
    saveToProfileLibraryAfterPersist: Bool = false,
    reason: String
  ) {
    importedWorkspacePersistTask?.cancel()
    importedWorkspacePersistTask = Task { [weak self] in
      await self?.persistImportedWorkspace(
        reason: reason,
        saveToProfileLibraryAfterPersist: saveToProfileLibraryAfterPersist
      )
    }
  }

  private func persistImportedWorkspace(
    reason: String,
    saveToProfileLibraryAfterPersist: Bool
  ) async {
    let shouldManageBusyState = !isBusy
    let importActivityMessage = L10n.string(
      "profiles.imports.applying",
      "Applying the imported configuration and syncing the runtime."
    )

    if shouldManageBusyState {
      isBusy = true
    }
    isApplyingImportedWorkspace = true
    refreshProxyPresentation()
    activityMessage = importActivityMessage
    lastError = nil
    SharedStore.appendLog(level: "info", message: reason)

    defer {
      isApplyingImportedWorkspace = false
      refreshProxyPresentation()
      if shouldManageBusyState {
        isBusy = false
      }
      if activityMessage == importActivityMessage {
        activityMessage = nil
      }
    }

    guard let report = await persistCurrentInput(showBusy: false, refreshRuntimeSnapshot: false) else {
      return
    }
    guard report.isValid else {
      return
    }
    guard !Task.isCancelled else { return }

    let remoteImportSource = lastRemoteImportSource?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !remoteImportSource.isEmpty {
      do {
        let record = try await upsertRemoteImportedProfile(remoteSource: remoteImportSource)
        draftProfileName = record.name
        SharedStore.appendLog(
          level: "info",
          message: "Updated the saved subscription '\(record.name)' from \(remoteImportSource) so it stays manageable in the profile library."
        )
        refreshProfileLibraryAsync()
      } catch {
        SharedStore.appendLog(
          level: "warning",
          message: "Imported configuration was persisted, but saving the subscription entry for \(remoteImportSource) failed: \(error.localizedDescription)"
        )
      }
    } else if saveToProfileLibraryAfterPersist {
      do {
        let record = try await profileLibraryCoordinator.upsertImportedProfile(
          input: currentInput(),
          fallbackName: preferredRemoteProfileName()
        )
        activeProfileRecordID = record.id
        draftProfileName = record.name
        lastRemoteImportSource = record.remoteSource
        refreshProfileLibraryAsync()
        SharedStore.appendLog(
          level: "info",
          message: "Saved the imported local profile as '\(record.name)' so it appears in the profile library immediately."
        )
      } catch {
        SharedStore.appendLog(
          level: "warning",
          message: "Imported configuration was persisted, but saving it into the profile library failed: \(error.localizedDescription)"
        )
      }
    }

    let liveObservation = await TunnelManager.shared.currentRuntimeObservation(fallback: runtimeStatus)
    guard !Task.isCancelled else { return }

    if runtimeStatus != liveObservation.runtimeStatus {
      runtimeStatus = liveObservation.runtimeStatus
    }
    if let liveExtensionSnapshot = liveObservation.extensionSnapshot {
      if extensionSnapshot != liveExtensionSnapshot {
        extensionSnapshot = liveExtensionSnapshot
      }
    } else if extensionSnapshot.startupAcceptedForAppOperations
      && !liveObservation.runtimeStatus.startupAcceptedForControllerWarmup {
      extensionSnapshot = TunnelExtensionSnapshot(
        runtimeStatus: liveObservation.runtimeStatus,
        startupPhase: liveObservation.runtimeStatus.startupPhase,
        startupMessage: liveObservation.runtimeStatus.startupMessage,
        lastFailureReason: liveObservation.runtimeStatus.lastFailureReason,
        lastFailurePhase: liveObservation.runtimeStatus.lastFailurePhase,
        lastStopReason: liveObservation.runtimeStatus.lastStopReason,
        controllerAddress: nil,
        phaseUpdatedAt: liveObservation.runtimeStatus.updatedAt,
        running: liveObservation.runtimeStatus.state == .running
      )
    }

    let liveControllerMetadata = SharedStore.readControllerMetadata()
    let shouldReloadRunningRuntime =
      liveObservation.runtimeStatus.state == .running
      || liveControllerMetadata.active
      || (liveObservation.extensionSnapshot?.startupAcceptedForAppOperations ?? false)

    if shouldReloadRunningRuntime {
      do {
        try await runtimeIO.reloadRuntime()
        SharedStore.appendLog(
          level: "info",
          message: "Imported configuration was hot-reloaded into the embedded runtime so the latest proxy groups become selectable without restarting the VPN tunnel."
        )
      } catch {
        lastError = error.localizedDescription
        SharedStore.appendLog(
          level: "warning",
          message: "Imported configuration was persisted, but the runtime hot-reload did not finish: \(error.localizedDescription)"
        )
      }
    } else {
      SharedStore.appendLog(
        level: "info",
        message: "Imported configuration was persisted without a runtime hot-reload because the embedded controller is not currently live. Start the VPN or wait for the current startup attempt to finish before requesting runtime actions."
      )
    }

    guard !Task.isCancelled else { return }
    refresh(refreshDerivedState: false)
  }

  private func resetProxySelectionStateForImportedWorkspace(
    resetPreferredProxySelections: Bool = true,
    clearPersistedProxyGroups: Bool = true
  ) {
    proxyPreviewTask?.cancel()
    derivedStateTask?.cancel()
    proxySelectionState.reset(resetPreferredSelections: resetPreferredProxySelections)
    proxyDelayTestingState.reset()
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    setProxyGroups([])
    setConnections([])
    clearRouteExplanationsForWorkspaceSwitch()
    proxyNodes = []
    displayedProxyNodes = []
    rules = []
    resources = []
    proxyCount = 0
    ruleCount = 0
    if clearPersistedProxyGroups {
      try? SharedStore.writeProxyGroups([])
    }
  }

  private func clearActiveWorkspaceAfterDeletingProfile(_ profile: ProfileBundleRecord) {
    importedWorkspacePersistTask?.cancel()
    activeProfileRecordID = nil
    lastPublishedInput = nil
    draftProfileName = L10n.string("profiles.default_name", "Default Profile")
    lastRemoteImportSource = nil

    let clearedInput = CompatibilityInput(
      profileYaml: Self.emptyProfile,
      controlledConfigYaml: controlledConfigYaml,
      appConfigJson: appConfigJson,
      overrideYaml: overrideYaml,
      overrideJavaScript: overrideJavaScript
    )
    apply(clearedInput)

    let clearedGroups = compatibilityService.extractProxyGroups(from: Self.emptyProfile)
    let clearedRules = compatibilityService.extractRules(from: Self.emptyProfile)
    setProxyGroups(clearedGroups)
    proxyNodes = []
    displayedProxyNodes = []
    rules = clearedRules
    resources = []
    proxyCount = 0
    ruleCount = clearedRules.count
    validationReport = compatibilityService.validate(currentInput())
    try? SharedStore.writeProxyGroups(clearedGroups)
    try? SharedStore.writeProxySelectionPreferences([:])

    schedulePersistImportedWorkspace(
      reason: "Deleted the active saved profile '\(profile.name)' and cleared its proxy nodes from the active workspace."
    )
  }

  private func resetProfileEditorExpansionIfNeeded(for yaml: String) {
    if yaml.lengthOfBytes(using: .utf8) > Self.largeProfileThresholdBytes {
      isProfileEditorExpanded = false
    }
  }

  func expandProfileEditor() {
    isProfileEditorExpanded = true
  }

  func collapseProfileEditor() {
    isProfileEditorExpanded = false
  }

  func proxyGroupSubtitle(for group: ProxyGroupSnapshot) -> String {
    proxyPresentationDeriver.groupSubtitle(for: group, context: proxyPresentationContext())
  }

  func proxyGroupDisplaySelection(for group: ProxyGroupSnapshot) -> String {
    proxyPresentationDeriver.groupDisplaySelection(for: group, context: proxyPresentationContext())
  }

  func proxyGroupDetailStatus(for group: ProxyGroupSnapshot) -> String {
    proxyPresentationDeriver.groupDetailStatus(for: group, context: proxyPresentationContext())
  }

  func proxyDelayStatus(for proxyName: String) -> ProxyDelayStatus? {
    proxyPresentationDeriver.proxyDelayStatus(for: proxyName, in: proxyDelayStatuses)
  }

  func proxyDelayStatus(for node: ProxyNodeRecord) -> ProxyDelayStatus? {
    proxyDelayStatus(for: node.name)
  }

  func proxyDelayStatus(forSelectedProxyIn group: ProxyGroupSnapshot) -> ProxyDelayStatus? {
    proxyDelayStatus(for: proxyGroupDisplaySelection(for: group))
  }

  func sortedProxyOptions(for group: ProxyGroupSnapshot) -> [String] {
    proxyPresentationDeriver.sortedProxyOptions(
      for: group,
      sortMode: proxyNodeSortMode,
      delayStatuses: proxyDelayStatuses
    )
  }

  func isSpeedTesting(group: ProxyGroupSnapshot) -> Bool {
    proxyDelayGroupsInFlight.contains(group.name)
  }

  func proxyGroup(named groupName: String) -> ProxyGroupSnapshot? {
    proxyGroupsByName[groupName]
  }

  var profileByteCount: Int {
    profileYaml.lengthOfBytes(using: .utf8)
  }

  var hasCurrentProfileWorkspace: Bool {
    proxyCount > 0
  }

  var currentProfileDisplayName: String {
    if let activeProfileRecordID,
       let activeProfile = savedProfiles.first(where: { $0.id == activeProfileRecordID }) {
      return activeProfile.name
    }
    if let lastRemoteImportSource = lastRemoteImportSource?
      .trimmingCharacters(in: .whitespacesAndNewlines),
      !lastRemoteImportSource.isEmpty {
      return lastRemoteImportSource
    }
    let trimmedName = draftProfileName.trimmingCharacters(in: .whitespacesAndNewlines)
    let defaultName = L10n.string("profiles.default_name", "Default Profile")
    if !trimmedName.isEmpty, trimmedName != defaultName {
      return trimmedName
    }
    if hasCurrentProfileWorkspace {
      return L10n.string("profiles.current.unsaved", "Unsaved Workspace")
    }
    return L10n.string("common.none", "None")
  }

  var isLargeProfile: Bool {
    profileByteCount > Self.largeProfileThresholdBytes
  }

  var shouldCollapseProfileEditor: Bool {
    isLargeProfile && !isProfileEditorExpanded
  }

  var allowsProxySelection: Bool {
    !isApplyingImportedWorkspace && !displayedProxyGroups.isEmpty
  }

  var allowsProxyDelayTesting: Bool {
    !isApplyingImportedWorkspace && (!displayedProxyGroups.isEmpty || !proxyNodes.isEmpty)
  }

  func allowsProxySelection(for group: ProxyGroupSnapshot) -> Bool {
    allowsProxySelection && group.supportsManualSelection
  }

  func proxySelectionHint(for group: ProxyGroupSnapshot) -> String? {
    proxyPresentationDeriver.proxySelectionHint(for: group, context: proxyPresentationContext())
  }

  var tunnelControlsDisabled: Bool {
    isBusy || isTunnelInteractionLocked
  }

  private func isControllerUnavailableError(_ error: Error) -> Bool {
    let message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !message.isEmpty else { return false }
    return message == L10n.string(
      "error.runtime.controller_unavailable",
      "The embedded controller is unavailable. Wait for VPN startup to finish and try again."
    )
  }

  private func proxyDelayFailureStatus(for error: Error) -> ProxyDelayStatus {
    isControllerUnavailableError(error) ? .controllerUnavailable : .unavailable
  }

  @discardableResult
  private func beginProxyGroupDelayTest(
    _ groupName: String,
    previewProxyNames: [String]
  ) -> Bool {
    guard proxyDelayTestingState.beginGroup(groupName, previewProxyNames: previewProxyNames) else {
      return false
    }
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
    return true
  }

  private func finishProxyGroupDelayTest(_ groupName: String) {
    proxyDelayTestingState.finishGroup(groupName)
    syncPublishedProxyDelayState()
    refreshProxyPresentation()
  }

  private func applyProxyGroupDelayMeasurements(
    previewProxyNames: [String],
    measurements: [String: Int]
  ) -> [String] {
    let measuredProxyNames = proxyDelayTestingState.applyGroupMeasurements(
      previewProxyNames: previewProxyNames,
      measurements: measurements
    )
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
    return measuredProxyNames
  }

  @discardableResult
  private func beginProxyNodeDelayTest(_ proxyName: String) -> Bool {
    guard proxyDelayTestingState.beginNode(proxyName) else { return false }
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
    return true
  }

  private func applyProxyNodeDelayMeasurement(proxyName: String, delay: Int) {
    proxyDelayTestingState.applyNodeMeasurement(proxyName: proxyName, delay: delay)
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
  }

  private func failProxyNodeDelayTest(proxyName: String, status: ProxyDelayStatus) {
    proxyDelayTestingState.failNode(proxyName: proxyName, status: status)
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
  }

  private func markProxyDelayStatuses(_ status: ProxyDelayStatus, for proxyNames: [String]) {
    proxyDelayTestingState.mark(status, for: proxyNames)
    syncPublishedProxyDelayState()
    proxyPresentationDeriver.invalidateSortCache()
    refreshDisplayedProxyNodes()
  }

  private func syncPublishedProxyDelayState() {
    if proxyDelayStatuses != proxyDelayTestingState.statuses {
      proxyDelayStatuses = proxyDelayTestingState.statuses
    }
    if proxyDelayGroupsInFlight != proxyDelayTestingState.groupsInFlight {
      proxyDelayGroupsInFlight = proxyDelayTestingState.groupsInFlight
    }
  }

  private func mergeDiscoveredProxyNodes(named proxyNames: [String]) {
    guard !proxyNames.isEmpty else { return }

    var knownNames = Set(
      proxyNodes.map { $0.name.trimmingCharacters(in: .whitespacesAndNewlines) }
    )
    var appendedNodes: [ProxyNodeRecord] = []

    for proxyName in proxyNames {
      guard proxyName.caseInsensitiveCompare("DIRECT") != .orderedSame else { continue }
      guard knownNames.insert(proxyName).inserted else { continue }
      appendedNodes.append(
        ProxyNodeRecord(
          id: "discovered-\(proxyName)",
          name: proxyName
        )
      )
    }

    guard !appendedNodes.isEmpty else { return }
    proxyNodes.append(contentsOf: appendedNodes)
    proxyCount = proxyNodes.count
    refreshDisplayedProxyNodes()
  }

  private func refreshDisplayedProxyNodes() {
    let nextDisplayedProxyNodes = proxyPresentationDeriver.displayedProxyNodes(
      from: proxyNodes,
      sortMode: proxyNodeSortMode,
      delayStatuses: proxyDelayStatuses,
      limit: Self.proxyNodeDisplayLimit
    )
    if displayedProxyNodes != nextDisplayedProxyNodes {
      displayedProxyNodes = nextDisplayedProxyNodes
    }
    refreshProxyPresentation()
  }

  private func materializedProxySelectionPreferences() -> [String: String] {
    materializedProxySelectionPreferences(within: proxyGroups)
  }

  private func materializedProxySelectionPreferences(
    within groups: [ProxyGroupSnapshot]
  ) -> [String: String] {
    ProxySelectionCoordinator.materializedPreferences(
      proxySelectionState.preferred,
      within: groups
    )
  }

  private func effectivePreferredSelection(
    for group: ProxyGroupSnapshot,
    within _: [ProxyGroupSnapshot]
  ) -> String? {
    preferredSelection(for: group.name)
  }

  private func resolvedRemoteProfileURL() -> String {
    let trimmed = remoteProfileURL.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed
  }

  private static func decodeRemoteProfilePayload(_ data: Data) throws -> String {
    func normalized(_ rawText: String) -> String {
      let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)

      if trimmed.contains("proxies:") || trimmed.contains("proxy-groups:") || trimmed.contains("rules:") {
        return trimmed
      }

      let compact = trimmed
        .replacingOccurrences(of: "\r", with: "")
        .replacingOccurrences(of: "\n", with: "")

      if let decodedData = Data(base64Encoded: compact),
         let decodedText = String(data: decodedData, encoding: .utf8)?
           .trimmingCharacters(in: .whitespacesAndNewlines),
         !decodedText.isEmpty
      {
        return decodedText
      }

      return trimmed
    }

    for encoding in [String.Encoding.utf8, .ascii] {
      if let text = String(data: data, encoding: encoding) {
        let payload = normalized(text)
        if !payload.isEmpty {
          return payload
        }
      }
    }

    throw RemoteImportError.emptyPayload
  }

  private static func mergeProxyTemplate(_ preset: ProxyTemplatePreset, into current: String) -> String {
    let trimmedCurrent = current.trimmingCharacters(in: .whitespacesAndNewlines)

    if trimmedCurrent.isEmpty || trimmedCurrent == defaultProfile.trimmingCharacters(in: .whitespacesAndNewlines) {
      return preset.starterBundle
    }

    if let range = current.range(of: "\nproxy-groups:") {
      return current.replacingCharacters(in: range, with: "\n\(preset.proxyBlock)\nproxy-groups:")
    }

    if current.contains("proxies:") {
      let suffix = current.hasSuffix("\n") ? "" : "\n"
      return "\(current)\(suffix)\(preset.proxyBlock)\n"
    }

    return """
    proxies:
    \(preset.proxyBlock)

    \(trimmedCurrent)
    """
  }

  private static func readTextFile(at url: URL) async throws -> String {
    try await Task.detached(priority: .userInitiated) {
      try String(contentsOf: url, encoding: .utf8)
    }.value
  }

  @discardableResult
  private func verifySharedStoreAvailable() -> Bool {
    let diagnostics = SharedStore.appGroupDiagnostics()
    sharedStoreDiagnostics = diagnostics
    refreshRuleInsightPresentation()
    ConsoleDiagnosticsWriter.shared.writeSharedStoreDiagnostics(diagnostics)
    guard diagnostics.isAvailable else {
      lastError = Self.sharedStoreUnavailableMessage(diagnostics)
      return false
    }
    return true
  }

  private static func sharedStoreUnavailableMessage(
    _ diagnostics: SharedStoreAppGroupDiagnostics
  ) -> String {
    L10n.format(
      "error.shared_store.unavailable",
      "The App Group container '%@' is unavailable, so Clash Party cannot publish the VPN runtime config. Reinstall a build signed with App Groups enabled. Detail: %@",
      diagnostics.appGroupIdentifier,
      diagnostics.errorDescription ?? "Unknown error"
    )
  }

}

extension ConsoleViewModel {
  static let largeProfileThresholdBytes = 128 * 1024
  static let defaultRemoteProfileURL =
    "http://192.168.1.3:25000/sub/stable"
  static let proxyDelayTestURL = "https://www.gstatic.com/generate_204"
  static let proxyDelayTimeoutMilliseconds = 5_000

  static let defaultProfile = emptyProfile

  static let emptyProfile = """
  proxies: []
  proxy-groups:
    - name: GLOBAL
      type: select
      proxies:
        - DIRECT
  rules:
    - MATCH,DIRECT
  """

  static let defaultControlledConfig = """
  mode: rule
  log-level: info
  geodata-mode: false
  geox-url:
    geoip: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat
    geosite: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat
    mmdb: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb
    asn: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb
  dns:
    enable: true
    enhanced-mode: fake-ip
    fake-ip-range: 198.19.0.1/16
    fake-ip-filter:
      - "*.lan"
      - "*.local"
      - localhost
      - "+.home.arpa"
    nameserver:
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    proxy-server-nameserver:
      - https://223.5.5.5/dns-query
    default-nameserver:
      - https://223.5.5.5/dns-query
    fallback-filter:
      geoip: false
    nameserver-policy:
      "geosite:cn":
        - 223.5.5.5
  tun:
    enable: true
    stack: system
    mtu: 1500
    auto-detect-interface: true
    dns-hijack:
      - any:53
      - tcp://any:53
  sniffer:
    enable: true
    force-dns-mapping: true
    parse-pure-ip: true
    override-destination: true
    sniff:
      TLS:
        ports:
          - 443
      HTTP:
        ports:
          - 80
  """

  static let defaultOverrideYAML = """
  # 按需添加分流、DNS 或资源提供者的 YAML 覆写。
  """

  static let defaultOverrideJavaScript = ""

  static let defaultAppConfig = """
  {
    "iosRoutingPolicy": "automatic"
  }
  """
}
