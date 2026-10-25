import Foundation
import SwiftUI

enum ProxyDelayStatus: Equatable, Sendable {
  case testing
  case available(Int)
  case unavailable
  case controllerUnavailable
}

enum ProxyNodeSortMode: String, CaseIterable, Identifiable {
  case profileOrder
  case latency

  var id: String { rawValue }
}

struct RouteExplanationMetrics: Codable, Equatable {
  var sampleCount: Int = 0
  var lastDurationMs: Double = 0
  var maxDurationMs: Double = 0
  var averageDurationMs: Double = 0

  var isWithinTarget: Bool {
    maxDurationMs <= 50
  }

  mutating func record(durationMs: Double) {
    sampleCount += 1
    lastDurationMs = durationMs
    maxDurationMs = max(maxDurationMs, durationMs)
    averageDurationMs += (durationMs - averageDurationMs) / Double(sampleCount)
  }
}

struct ProxyPresentationState: Equatable {
  var runtimeMode: String = "rule"
  var fakeDnsEnabled: Bool = false
  var backend: String = "unknown"
  var displayedGroups: [ProxyGroupSnapshot] = []
  var sortedOptionsByGroupName: [String: [ProxyOptionPresentationRecord]] = [:]
  var displayedNodes: [ProxyNodeRecord] = []
  var groupDisplaySelections: [String: String] = [:]
  var groupDetailStatuses: [String: String] = [:]
  var groupSelectionHints: [String: String] = [:]
  var totalProxyNodeCount: Int = 0
  var sortMode: ProxyNodeSortMode = .profileOrder
  var delayStatuses: [String: ProxyDelayStatus] = [:]
  var speedTestingGroupNames: Set<String> = []
  var isApplyingImportedWorkspace: Bool = false

  var displayedNodeLimitMessage: String? {
    guard totalProxyNodeCount > displayedNodes.count else { return nil }
    switch sortMode {
    case .profileOrder:
      return L10n.format(
        "proxies.nodes.preview_limit.profile_order",
        "Showing the first %d of %d nodes in subscription order to keep scrolling responsive.",
        displayedNodes.count,
        totalProxyNodeCount
      )
    case .latency:
      return L10n.format(
        "proxies.nodes.preview_limit.latency",
        "Showing the fastest known %d of %d nodes. Untested nodes stay behind tested latency results.",
        displayedNodes.count,
        totalProxyNodeCount
      )
    }
  }

  var allowsProxySelection: Bool {
    !isApplyingImportedWorkspace && !displayedGroups.isEmpty
  }

  var allowsProxyDelayTesting: Bool {
    !isApplyingImportedWorkspace && (!displayedGroups.isEmpty || !displayedNodes.isEmpty)
  }

  func proxyDelayStatus(for proxyName: String) -> ProxyDelayStatus? {
    let normalizedProxyName = proxyName.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedProxyName.isEmpty else { return nil }
    return delayStatuses[normalizedProxyName]
  }

  func proxyDelayStatus(for node: ProxyNodeRecord) -> ProxyDelayStatus? {
    proxyDelayStatus(for: node.name)
  }

  func proxyDelayStatus(forSelectedProxyIn group: ProxyGroupSnapshot, selectedProxyName: String) -> ProxyDelayStatus? {
    proxyDelayStatus(for: selectedProxyName)
  }

  func proxyGroupDisplaySelection(for group: ProxyGroupSnapshot) -> String {
    groupDisplaySelections[group.name] ?? group.selected ?? ""
  }

  func proxyGroupDetailStatus(for group: ProxyGroupSnapshot) -> String {
    groupDetailStatuses[group.name] ?? ""
  }

  func proxySelectionHint(for group: ProxyGroupSnapshot) -> String? {
    groupSelectionHints[group.name]
  }

  func isSpeedTesting(group: ProxyGroupSnapshot) -> Bool {
    speedTestingGroupNames.contains(group.name)
  }

  func allowsProxySelection(for group: ProxyGroupSnapshot) -> Bool {
    allowsProxySelection && group.supportsManualSelection
  }

  func proxyGroup(named groupName: String) -> ProxyGroupSnapshot? {
    displayedGroups.first { $0.name == groupName }
  }

  func sortedOptions(for group: ProxyGroupSnapshot) -> [ProxyOptionPresentationRecord] {
    sortedOptionsByGroupName[group.name] ?? group.displayOptions
      .map { ProxyOptionPresentationRecord(groupName: group.name, name: $0) }
  }
}

@MainActor
final class ProxyPresentationModel: ObservableObject {
  @Published private(set) var state = ProxyPresentationState()

  func update(_ nextState: ProxyPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct RuleInsightPresentationState: Equatable {
  var runtimeState: RuntimeConnectionState = .idle
  var runtimeMode: String = "rule"
  var vpnConnected: Bool = false
  var fakeDnsEnabled: Bool = false
  var connectionCount: Int = 0
  var usingRecentSnapshot: Bool = false
  var controllerAddress: String?
  var sharedStoreDiagnostics: SharedStoreAppGroupDiagnostics = .init(
    appGroupIdentifier: SharedStore.appGroupIdentifier,
    isAvailable: false,
    containerPath: nil,
    errorDescription: nil
  )
  var explanations: [RouteExplanation] = []
  var proxiedCount: Int = 0
  var hiddenCount: Int = 0
  var metrics: RouteExplanationMetrics = .init()
}

@MainActor
final class RuleInsightPresentationModel: ObservableObject {
  @Published private(set) var state = RuleInsightPresentationState()

  func update(_ nextState: RuleInsightPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct ShellPresentationState: Equatable {
  var activityMessage: String?
  var isShowingActivity: Bool = false
}

@MainActor
final class ShellPresentationModel: ObservableObject {
  @Published private(set) var state = ShellPresentationState()

  func update(_ nextState: ShellPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct OverviewPresentationState: Equatable {
  var runtimeState: RuntimeConnectionState = .idle
  var runtimeMode: String = "rule"
  var fakeDnsEnabled: Bool = false
  var vpnConnected: Bool = false
  var dataPlaneReady: Bool = false
  var hasProxyNodes: Bool = false
  var tunnelControlsDisabled: Bool = false
  var activeProxySummary: String = L10n.string("common.none", "None")
  var currentProfileSummary: String = L10n.string("common.none", "None")
  var runtimePhaseSummary: String = L10n.string("runtime.phase.idle", "Runtime is idle.")
  var planStartupMessage: String = ""
  var diagnosticStartupMessage: String = ""
  var lastFailureReason: String?
  var lastFailurePhase: String?
  var lastStopReason: String?
  var lastError: String?
  var lastRemoteImportSource: String?
  var trafficSummary: String = L10n.format(
    "overview.metrics.traffic_summary",
    "%@ down · %@ up",
    DisplayValue.bytes(0),
    DisplayValue.bytes(0)
  )

  var shouldShowStartupDiagnostics: Bool {
    !diagnosticStartupMessage.isEmpty || lastFailureReason != nil || lastStopReason != nil
  }
}

@MainActor
final class OverviewPresentationModel: ObservableObject {
  @Published private(set) var state = OverviewPresentationState()

  func update(_ nextState: OverviewPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct ConnectionsPresentationState: Equatable {
  var connections: [ConnectionSnapshot] = []
}

@MainActor
final class ConnectionsPresentationModel: ObservableObject {
  @Published private(set) var state = ConnectionsPresentationState()

  func update(_ nextState: ConnectionsPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct LogPresentationRecord: Identifiable, Equatable {
  let id: String
  let timestamp: String
  let level: String
  let message: String
}

struct LogsPresentationState: Equatable {
  var records: [LogPresentationRecord] = []
  var totalCount: Int = 0

  var isEmpty: Bool { records.isEmpty }
  var hiddenCount: Int { max(0, totalCount - records.count) }
}

@MainActor
final class LogsPresentationModel: ObservableObject {
  @Published private(set) var state = LogsPresentationState()

  func update(_ nextState: LogsPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct ProxyOptionPresentationRecord: Identifiable, Equatable {
  let id: String
  let name: String

  init(groupName: String, name: String) {
    self.name = name
    id = "\(groupName)::\(name)"
  }
}

struct RulePresentationRecord: Identifiable, Equatable {
  let id: String
  let rule: RuleMatchRecord
}

struct RulesPresentationState: Equatable {
  var records: [RulePresentationRecord] = []
  var totalCount: Int = 0

  var isEmpty: Bool { records.isEmpty }
  var hiddenCount: Int { max(0, totalCount - records.count) }
}

@MainActor
final class RulesPresentationModel: ObservableObject {
  @Published private(set) var state = RulesPresentationState()

  func update(_ nextState: RulesPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct DnsPresentationState: Equatable {
  var summary: DnsSummary = .init()
  var controlledConfigYaml: String = ""
}

@MainActor
final class DnsPresentationModel: ObservableObject {
  @Published private(set) var state = DnsPresentationState()

  func update(_ nextState: DnsPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct ResourcesPresentationState: Equatable {
  var resources: [ResourceRecord] = []

  var isEmpty: Bool { resources.isEmpty }
}

@MainActor
final class ResourcesPresentationModel: ObservableObject {
  @Published private(set) var state = ResourcesPresentationState()

  func update(_ nextState: ResourcesPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct CorePresentationState: Equatable {
  var mihomoSummary: MihomoSummary = .init()
  var tunSummary: TunSummary = .init()
}

@MainActor
final class CorePresentationModel: ObservableObject {
  @Published private(set) var state = CorePresentationState()

  func update(_ nextState: CorePresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct SubStorePresentationState: Equatable {
  var summary: SubStoreSummary = .init()
  var isBusy: Bool = false
}

@MainActor
final class SubStorePresentationModel: ObservableObject {
  @Published private(set) var state = SubStorePresentationState()

  func update(_ nextState: SubStorePresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct SettingsPresentationState: Equatable {
  var preservedButInactiveFields: [String] = []
  var exportBundleName: String = ""
  var lastExportPath: String?
  var appConfigJson: String = ""
}

@MainActor
final class SettingsPresentationModel: ObservableObject {
  @Published private(set) var state = SettingsPresentationState()

  func update(_ nextState: SettingsPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct ProfilesPresentationState: Equatable {
  var currentProfileDisplayName: String = L10n.string("common.none", "None")
  var savedProfiles: [ProfileBundleRecord] = []
  var lastExportPath: String?
  var lastRemoteImportSource: String?
  var draftProfileName: String = ""
  var remoteProfileURL: String = ""
  var isBusy: Bool = false
  var shouldCollapseProfileEditor: Bool = false
  var isLargeProfile: Bool = false
  var profileByteCount: Int = 0
  var proxyCount: Int = 0
  var ruleCount: Int = 0
  var profileYaml: String = ""
  var controlledConfigYaml: String = ""
  var draftBackupName: String = ""
  var backups: [BackupRecord] = []

  var remoteProfileURLIsBlank: Bool {
    remoteProfileURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }
}

@MainActor
final class ProfilesPresentationModel: ObservableObject {
  @Published private(set) var state = ProfilesPresentationState()

  func update(_ nextState: ProfilesPresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

struct OverridePresentationState: Equatable {
  var overrideYaml: String = ""
  var overrideJavaScript: String = ""
}

@MainActor
final class OverridePresentationModel: ObservableObject {
  @Published private(set) var state = OverridePresentationState()

  func update(_ nextState: OverridePresentationState) {
    guard state != nextState else { return }
    state = nextState
  }
}

private struct ProxyDelaySortKey: Comparable {
  let bucket: Int
  let delay: Int
  let originalIndex: Int

  static func < (lhs: ProxyDelaySortKey, rhs: ProxyDelaySortKey) -> Bool {
    if lhs.bucket != rhs.bucket {
      return lhs.bucket < rhs.bucket
    }
    if lhs.delay != rhs.delay {
      return lhs.delay < rhs.delay
    }
    return lhs.originalIndex < rhs.originalIndex
  }
}

private struct CachedSortedProxyOptions {
  let group: ProxyGroupSnapshot
  let sortMode: ProxyNodeSortMode
  let delayStatuses: [String: ProxyDelayStatus]
  let options: [String]
}

struct ProxyPresentationContext {
  var runtimeStatus: RuntimeStatus
  var displayedGroups: [ProxyGroupSnapshot]
  var displayedNodes: [ProxyNodeRecord]
  var totalProxyNodeCount: Int
  var sortMode: ProxyNodeSortMode
  var delayStatuses: [String: ProxyDelayStatus]
  var speedTestingGroupNames: Set<String>
  var isApplyingImportedWorkspace: Bool
  var activeSelection: ProxySelectionRequest?
  var pendingSelections: [ProxySelectionRequest]
  var confirmedSelections: [String: String]
  var preferredSelections: [String: String]
  var runtimeCanAcceptProxySelectionSoon: Bool
  var pendingWaitReason: ProxySelectionWaitReason?
}

struct ProxyPresentationDeriver {
  private var sortedOptionsCache: [String: CachedSortedProxyOptions] = [:]

  mutating func invalidateSortCache() {
    sortedOptionsCache.removeAll()
  }

  static func visibleProxyGroups(
    from groups: [ProxyGroupSnapshot],
    mode: String
  ) -> [ProxyGroupSnapshot] {
    let manualGroups = groups.filter {
      $0.name.caseInsensitiveCompare("GLOBAL") != .orderedSame && $0.supportsManualSelection
    }
    guard mode.lowercased() != "global", !manualGroups.isEmpty else {
      return groups
    }
    return groups.filter { $0.name.caseInsensitiveCompare("GLOBAL") != .orderedSame }
  }

  static func uniqueProxyNames(from names: [String]) -> [String] {
    ProxyNameNormalizer.uniqueDisplayOptions(from: names)
  }

  static func normalizedProxyDelayMeasurements(_ measurements: [String: Int]) -> [String: Int] {
    measurements.reduce(into: [String: Int]()) { result, item in
      let proxyName = item.key.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !proxyName.isEmpty else { return }
      result[proxyName] = item.value
    }
  }

  func proxyDelayStatus(
    for proxyName: String,
    in delayStatuses: [String: ProxyDelayStatus]
  ) -> ProxyDelayStatus? {
    let normalizedProxyName = proxyName.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalizedProxyName.isEmpty else { return nil }
    return delayStatuses[normalizedProxyName]
  }

  func proxyDelaySummary(
    for proxyName: String,
    delayStatuses: [String: ProxyDelayStatus]
  ) -> String? {
    switch proxyDelayStatus(for: proxyName, in: delayStatuses) {
    case .testing?:
      return L10n.string("proxies.delay.testing", "Testing...")
    case .available(let delay)?:
      return "\(delay) ms"
    case .controllerUnavailable?:
      return L10n.string("proxies.delay.controller_offline", "Controller Offline")
    case .unavailable?:
      return L10n.string("proxies.delay.unavailable", "Timeout")
    case .none:
      return nil
    }
  }

  mutating func makeState(_ context: ProxyPresentationContext) -> ProxyPresentationState {
    let groupDisplaySelections = context.displayedGroups.reduce(into: [String: String]()) { result, group in
      result[group.name] = groupDisplaySelection(for: group, context: context)
    }
    let groupDetailStatuses = context.displayedGroups.reduce(into: [String: String]()) { result, group in
      result[group.name] = groupDetailStatus(for: group, context: context)
    }
    let groupSelectionHints = context.displayedGroups.reduce(into: [String: String]()) { result, group in
      if let hint = proxySelectionHint(for: group, context: context) {
        result[group.name] = hint
      }
    }
    let sortedOptionsByGroupName = context.displayedGroups.reduce(into: [String: [ProxyOptionPresentationRecord]]()) { result, group in
      result[group.name] = sortedProxyOptions(
        for: group,
        sortMode: context.sortMode,
        delayStatuses: context.delayStatuses
      ).map { ProxyOptionPresentationRecord(groupName: group.name, name: $0) }
    }

    return ProxyPresentationState(
      runtimeMode: context.runtimeStatus.mode,
      fakeDnsEnabled: context.runtimeStatus.fakeDnsEnabled,
      backend: context.runtimeStatus.backend,
      displayedGroups: context.displayedGroups,
      sortedOptionsByGroupName: sortedOptionsByGroupName,
      displayedNodes: context.displayedNodes,
      groupDisplaySelections: groupDisplaySelections,
      groupDetailStatuses: groupDetailStatuses,
      groupSelectionHints: groupSelectionHints,
      totalProxyNodeCount: context.totalProxyNodeCount,
      sortMode: context.sortMode,
      delayStatuses: context.delayStatuses,
      speedTestingGroupNames: context.speedTestingGroupNames,
      isApplyingImportedWorkspace: context.isApplyingImportedWorkspace
    )
  }

  func groupSubtitle(for group: ProxyGroupSnapshot, context: ProxyPresentationContext) -> String {
    let activeSelection = activeSelection(for: group, context: context)
    let activeDisplay = activeSelection.isEmpty
      ? L10n.string("common.none", "None")
      : activeSelection

    if let activeProxySelection = context.activeSelection,
       activeProxySelection.groupName == group.name {
      return "Applying \(activeProxySelection.proxy). Active now: \(activeDisplay)."
    }

    if let queuedRequest = context.pendingSelections.last(where: { $0.groupName == group.name }) {
      return "Queued \(queuedRequest.proxy). Active now: \(activeDisplay)."
    }

    if !group.supportsManualSelection {
      return "Managed automatically by the runtime. Active now: \(activeDisplay)."
    }

    if !context.runtimeCanAcceptProxySelectionSoon,
       let preferred = preferredSelection(for: group, context: context),
       preferred != activeSelection {
      return "Next connect will use \(preferred). Active now: \(activeDisplay)."
    }

    if let preferred = preferredSelection(for: group, context: context),
       preferred != activeSelection {
      return "Preferred \(preferred). Active now: \(activeDisplay)."
    }

    if let delaySummary = proxyDelaySummary(for: activeSelection, delayStatuses: context.delayStatuses),
       !activeSelection.isEmpty {
      return "Selected: \(activeDisplay) · \(delaySummary)"
    }

    return L10n.format("proxies.group.subtitle", "Selected: %@", activeDisplay)
  }

  func groupDisplaySelection(
    for group: ProxyGroupSnapshot,
    context: ProxyPresentationContext
  ) -> String {
    if let activeProxySelection = context.activeSelection,
       activeProxySelection.groupName == group.name,
       ProxySelectionCoordinator.isSelection(activeProxySelection.proxy, validFor: group) {
      return activeProxySelection.proxy
    }

    if let queuedRequest = context.pendingSelections.last(where: { $0.groupName == group.name }),
       ProxySelectionCoordinator.isSelection(queuedRequest.proxy, validFor: group) {
      return queuedRequest.proxy
    }

    if let preferred = preferredSelection(for: group, context: context),
       ProxySelectionCoordinator.isSelection(preferred, validFor: group),
       !context.runtimeCanAcceptProxySelectionSoon {
      return preferred
    }

    return activeSelection(for: group, context: context)
  }

  func groupDetailStatus(
    for group: ProxyGroupSnapshot,
    context: ProxyPresentationContext
  ) -> String {
    let activeSelection = activeSelection(for: group, context: context)
    let activeDisplay = activeSelection.isEmpty
      ? L10n.string("common.none", "None")
      : activeSelection

    if let activeProxySelection = context.activeSelection,
       activeProxySelection.groupName == group.name {
      return L10n.format(
        "proxies.group.detail.applying",
        "Applying %@. Active now: %@.",
        activeProxySelection.proxy,
        activeDisplay
      )
    }

    if let queuedRequest = context.pendingSelections.last(where: { $0.groupName == group.name }) {
      return L10n.format(
        "proxies.group.detail.queued",
        "Queued %@. Active now: %@.",
        queuedRequest.proxy,
        activeDisplay
      )
    }

    if !group.supportsManualSelection {
      return L10n.format(
        "proxies.group.detail.auto",
        "The runtime manages this group automatically. Active now: %@.",
        activeDisplay
      )
    }

    if !context.runtimeCanAcceptProxySelectionSoon,
       let preferred = preferredSelection(for: group, context: context),
       preferred != activeSelection {
      return L10n.format(
        "proxies.group.detail.next_connect",
        "Next connect will use %@. Active now: %@.",
        preferred,
        activeDisplay
      )
    }

    if let preferred = preferredSelection(for: group, context: context),
       preferred != activeSelection {
      return L10n.format(
        "proxies.group.detail.preferred",
        "Preferred %@. Active now: %@.",
        preferred,
        activeDisplay
      )
    }

    return L10n.string(
      "proxies.group.detail.ready",
      "Choose one node below, or run Test All from the toolbar to refresh latency."
    )
  }

  func proxySelectionHint(
    for group: ProxyGroupSnapshot,
    context: ProxyPresentationContext
  ) -> String? {
    guard !context.displayedGroups.isEmpty else { return nil }
    if !group.supportsManualSelection {
      return L10n.string(
        "proxies.group.auto_managed",
        "This proxy group is managed automatically by the runtime and cannot be pinned manually."
      )
    }
    if context.isApplyingImportedWorkspace {
      return L10n.string(
        "proxies.group.apply_in_progress",
        "Proxy-group selections are temporarily unavailable while the imported configuration is being applied."
      )
    }
    if context.pendingWaitReason == .controllerWarmup {
      return L10n.string(
        "proxies.group.controller_warming",
        "The embedded controller is still warming up. Your latest selection is queued and will apply automatically."
      )
    }
    if context.pendingWaitReason == .providerWarmup {
      return L10n.string(
        "proxies.group.provider_warming",
        "The selected node is still loading from its proxy provider. Your latest selection is queued and will apply automatically."
      )
    }
    if !context.runtimeCanAcceptProxySelectionSoon {
      return L10n.string(
        "proxies.group.offline_saved",
        "Offline selections are saved as the next-connect preference and will be applied automatically after the VPN starts."
      )
    }
    return nil
  }

  mutating func sortedProxyOptions(
    for group: ProxyGroupSnapshot,
    sortMode: ProxyNodeSortMode,
    delayStatuses: [String: ProxyDelayStatus]
  ) -> [String] {
    let relevantDelayStatuses = relevantDelayStatuses(for: group.displayOptions, delayStatuses: delayStatuses)
    if let cached = sortedOptionsCache[group.name],
       cached.group == group,
       cached.sortMode == sortMode,
       cached.delayStatuses == relevantDelayStatuses {
      return cached.options
    }

    let options = sortedProxyNames(group.displayOptions, sortMode: sortMode, delayStatuses: delayStatuses)
    sortedOptionsCache[group.name] = CachedSortedProxyOptions(
      group: group,
      sortMode: sortMode,
      delayStatuses: relevantDelayStatuses,
      options: options
    )
    return options
  }

  func displayedProxyNodes(
    from nodes: [ProxyNodeRecord],
    sortMode: ProxyNodeSortMode,
    delayStatuses: [String: ProxyDelayStatus],
    limit: Int
  ) -> [ProxyNodeRecord] {
    Array(
      sortedProxyNodes(
        nodes,
        sortMode: sortMode,
        delayStatuses: delayStatuses
      )
      .prefix(limit)
    )
  }

  private func sortedProxyNodes(
    _ nodes: [ProxyNodeRecord],
    sortMode: ProxyNodeSortMode,
    delayStatuses: [String: ProxyDelayStatus]
  ) -> [ProxyNodeRecord] {
    guard sortMode == .latency else { return nodes }
    let originalIndexes = nodes.enumerated().reduce(into: [String: Int]()) { result, item in
      let normalizedName = item.element.name.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !normalizedName.isEmpty, result[normalizedName] == nil else { return }
      result[normalizedName] = item.offset
    }

    return nodes.sorted { lhs, rhs in
      delaySortKey(
        for: lhs.name,
        originalIndex: originalIndexes[lhs.name.trimmingCharacters(in: .whitespacesAndNewlines)] ?? 0,
        delayStatuses: delayStatuses
      )
        < delaySortKey(
          for: rhs.name,
          originalIndex: originalIndexes[rhs.name.trimmingCharacters(in: .whitespacesAndNewlines)] ?? 0,
          delayStatuses: delayStatuses
        )
    }
  }

  private func sortedProxyNames(
    _ names: [String],
    sortMode: ProxyNodeSortMode,
    delayStatuses: [String: ProxyDelayStatus]
  ) -> [String] {
    guard sortMode == .latency else { return names }
    let originalIndexes = names.enumerated().reduce(into: [String: Int]()) { result, item in
      let normalizedName = item.element.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !normalizedName.isEmpty, result[normalizedName] == nil else { return }
      result[normalizedName] = item.offset
    }

    return names.sorted { lhs, rhs in
      delaySortKey(
        for: lhs,
        originalIndex: originalIndexes[lhs.trimmingCharacters(in: .whitespacesAndNewlines)] ?? 0,
        delayStatuses: delayStatuses
      )
        < delaySortKey(
          for: rhs,
          originalIndex: originalIndexes[rhs.trimmingCharacters(in: .whitespacesAndNewlines)] ?? 0,
          delayStatuses: delayStatuses
        )
    }
  }

  private func relevantDelayStatuses(
    for proxyNames: [String],
    delayStatuses: [String: ProxyDelayStatus]
  ) -> [String: ProxyDelayStatus] {
    proxyNames.reduce(into: [String: ProxyDelayStatus]()) { result, rawName in
      let normalizedName = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !normalizedName.isEmpty, let status = delayStatuses[normalizedName] else { return }
      result[normalizedName] = status
    }
  }

  private func delaySortKey(
    for proxyName: String,
    originalIndex: Int,
    delayStatuses: [String: ProxyDelayStatus]
  ) -> ProxyDelaySortKey {
    let normalizedName = proxyName.trimmingCharacters(in: .whitespacesAndNewlines)
    switch delayStatuses[normalizedName] {
    case .available(let delay)?:
      return ProxyDelaySortKey(bucket: 0, delay: delay, originalIndex: originalIndex)
    case .testing?:
      return ProxyDelaySortKey(bucket: 1, delay: Int.max, originalIndex: originalIndex)
    case .none:
      return ProxyDelaySortKey(bucket: 2, delay: Int.max, originalIndex: originalIndex)
    case .controllerUnavailable?, .unavailable?:
      return ProxyDelaySortKey(bucket: 3, delay: Int.max, originalIndex: originalIndex)
    }
  }

  private func activeSelection(
    for group: ProxyGroupSnapshot,
    context: ProxyPresentationContext
  ) -> String {
    context.confirmedSelections[group.name]
      ?? group.selected?
        .trimmingCharacters(in: .whitespacesAndNewlines)
      ?? ""
  }

  private func preferredSelection(
    for group: ProxyGroupSnapshot,
    context: ProxyPresentationContext
  ) -> String? {
    context.preferredSelections[group.name]
  }
}

private struct RouteExplanationInput: Equatable {
  var connections: [ConnectionSnapshot]
  var connectionCount: Int
  var fakeDnsEnabled: Bool
  var fakeIPRange: String
}

struct RouteInsightDerivation {
  var explanations: [RouteExplanation]
  var proxiedCount: Int
  var hiddenCount: Int
  var metrics: RouteExplanationMetrics
}

struct RouteInsightDeriver {
  let limit: Int
  private var lastInput: RouteExplanationInput?
  private var lastPersistedExplanations: [RouteExplanation] = []
  private var recentConnections: [ConnectionSnapshot] = []
  private(set) var metrics = RouteExplanationMetrics()

  init(limit: Int) {
    self.limit = limit
  }

  mutating func seed(_ explanations: [RouteExplanation]) {
    lastPersistedExplanations = explanations
  }

  mutating func rebuild(
    connections: [ConnectionSnapshot],
    fakeDnsEnabled: Bool,
    fakeIPRange: String
  ) -> RouteInsightDerivation? {
    let displayedConnections = Array(connections.prefix(limit))
    if !displayedConnections.isEmpty {
      recentConnections = displayedConnections
    }

    let sourceConnections = displayedConnections.isEmpty && connections.isEmpty
      ? recentConnections
      : displayedConnections
    let persistedExplanations = sourceConnections.isEmpty ? lastPersistedExplanations : []
    let input = RouteExplanationInput(
      connections: sourceConnections,
      connectionCount: connections.count,
      fakeDnsEnabled: fakeDnsEnabled,
      fakeIPRange: fakeIPRange
    )
    guard input != lastInput || persistedExplanations != lastPersistedExplanations else { return nil }
    lastInput = input
    lastPersistedExplanations = persistedExplanations

    let startTime = Date()
    let explanations: [RouteExplanation]
    if sourceConnections.isEmpty, !persistedExplanations.isEmpty {
      explanations = persistedExplanations
    } else {
      explanations = RouteExplanationResolver.explain(
        sourceConnections,
        fakeDnsEnabled: fakeDnsEnabled,
        fakeIPRange: fakeIPRange
      )
    }
    metrics.record(durationMs: Date().timeIntervalSince(startTime) * 1000)

    return RouteInsightDerivation(
      explanations: explanations,
      proxiedCount: RouteExplanationResolver.proxiedCount(in: explanations),
      hiddenCount: max(0, connections.count - displayedConnections.count),
      metrics: metrics
    )
  }
}
