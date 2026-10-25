import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
  guard condition() else {
    fputs("FAIL: \(message)\n", stderr)
    exit(1)
  }
}

@main
struct IOSSpeedtestAndProfilesRegressionCheck {
  static func main() {
    let profileYAML = """
    proxies:
      - name: HK-01
        type: socks5
        server: 127.0.0.1
        port: 1080
    proxy-groups:
      - type: url-test
        name: GLOBAL
        url: https://cp.cloudflare.com/generate_204
        proxies:
          - HK-01
          - DIRECT
    rules:
      - MATCH,GLOBAL
    """

    let compatibilityService = CompatibilityService()
    let groups = compatibilityService.extractProxyGroups(from: profileYAML)
    expect(groups.first?.testURL == "https://cp.cloudflare.com/generate_204", "proxy group test URL should be preserved from profile YAML")

    let appConfigJSON = """
    {
      "delayTestUrl": "https://fallback.example.com/generate_204",
      "delayTestTimeout": 9000
    }
    """
    let resolvedDelayTest = compatibilityService.resolveDelayTestSettings(
      preferredURL: groups.first?.testURL,
      appConfigJson: appConfigJSON
    )
    expect(resolvedDelayTest.url == "https://cp.cloudflare.com/generate_204", "group test URL should win over app-config fallback URL")
    expect(resolvedDelayTest.timeoutMilliseconds == 9000, "delay test timeout should come from app config")

    let networkPlanWithoutTunIPv6 = compatibilityService.makePacketTunnelNetworkPlan(
      from: """
      mode: rule
      ipv6: true
      dns:
        enable: true
        enhanced-mode: fake-ip
        fake-ip-range: 198.18.0.1/16
      tun:
        enable: true
        stack: system
        dns-hijack:
          - any:53
      """
    )
    expect(networkPlanWithoutTunIPv6.tunnelRemoteAddress == "172.31.255.2", "packet tunnel remote address should use a tunnel peer outside the fake-ip pool")
    expect(networkPlanWithoutTunIPv6.ipv4Address == "172.31.255.1", "packet tunnel local address must not overlap the fake-ip pool")
    expect(networkPlanWithoutTunIPv6.ipv6Address == nil, "packet tunnel should not advertise IPv6 when tun.inet6-address is absent")
    expect(networkPlanWithoutTunIPv6.dnsServers == ["172.31.255.2"], "packet tunnel should not publish a synthetic IPv6 DNS server when the core has no IPv6 tun address")

    let networkPlanWithTunIPv6 = compatibilityService.makePacketTunnelNetworkPlan(
      from: """
      mode: rule
      ipv6: true
      dns:
        enable: true
        enhanced-mode: fake-ip
        fake-ip-range: 198.18.0.1/16
      tun:
        enable: true
        stack: system
        inet6-address:
          - fdfe:dcba:9876::1/126
        dns-hijack:
          - any:53
      """
    )
    expect(networkPlanWithTunIPv6.ipv6Address == "fdfe:dcba:9876::1", "packet tunnel should keep IPv6 enabled when tun.inet6-address is present")
    expect(networkPlanWithTunIPv6.dnsServers == ["172.31.255.2", "fdfe:dcba:9876::2"], "packet tunnel should publish the IPv6 DNS server only when the tun IPv6 address exists")

    let networkPlanWithTopLevelIPv6AfterTun = compatibilityService.makePacketTunnelNetworkPlan(
      from: """
      dns:
        enable: true
        enhanced-mode: fake-ip
        fake-ip-range: 198.18.0.1/16
      tun:
        enable: true
      mode: rule
      inet6-address:
        - fdfe:dcba:9876::1/126
      """
    )
    expect(networkPlanWithTopLevelIPv6AfterTun.ipv6Address == nil, "top-level inet6-address after tun must not be parsed as tun.inet6-address")
    expect(networkPlanWithTopLevelIPv6AfterTun.dnsServers == ["172.31.255.2"], "top-level inet6-address after tun must not enable the synthetic IPv6 DNS server")

    let dnsSummaryWithTopLevelFallback = compatibilityService.parseDnsSummary(
      from: """
      dns:
        enable: true
        nameserver:
          - 1.1.1.1
      mode: rule
      fallback:
        - 8.8.8.8
      """
    )
    expect(dnsSummaryWithTopLevelFallback.fallbackServers.isEmpty, "top-level fallback after dns must not be parsed as dns.fallback")

    let scriptURL = URL(fileURLWithPath: #filePath)
    let projectRootURL = scriptURL.deletingLastPathComponent().deletingLastPathComponent()
    let consoleViewModelURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleViewModel.swift")
    let consolePresentationDeriversURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsolePresentationDerivers.swift")
    let consoleRuntimeIOURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleRuntimeIO.swift")
    let consoleProxySelectionURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleProxySelection.swift")
    let consoleDiagnosticsWriterURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleDiagnosticsWriter.swift")
    let consoleProxyDelayTestingURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleProxyDelayTesting.swift")
    let consoleProfileLibraryCoordinatorURL = projectRootURL.appendingPathComponent("ClashParty/ViewModels/ConsoleProfileLibraryCoordinator.swift")
    let runtimeModelsURL = projectRootURL.appendingPathComponent("ClashPartyShared/Models/RuntimeModels.swift")
    let appPagesURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppPages.swift")
    let appShellURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppShellView.swift")
    let appDesignSystemURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppDesignSystem.swift")
    let contentViewURL = projectRootURL.appendingPathComponent("ClashParty/Views/ContentView.swift")
    let sharedStoreURL = projectRootURL.appendingPathComponent("ClashPartyShared/Store/SharedStore.swift")
    let compatibilityServiceURL = projectRootURL.appendingPathComponent("ClashPartyShared/Compatibility/CompatibilityService.swift")
    let runtimeBridgeProtocolURL = projectRootURL.appendingPathComponent("ClashPartyShared/Runtime/RuntimeBridge.swift")
    let runtimeBridgeURL = projectRootURL.appendingPathComponent("ClashPartyShared/Runtime/MihomoRuntimeBridge.swift")
    let geoResourceManagerURL = projectRootURL.appendingPathComponent("ClashPartyShared/Runtime/GeoResourceManager.swift")
    let packetTunnelProviderURL = projectRootURL.appendingPathComponent("ClashPartyTunnel/PacketTunnelProvider.swift")
    let goCoreRootURL = projectRootURL
      .deletingLastPathComponent()
      .appendingPathComponent("mihomo-go-core")
    let singTunServerURL = goCoreRootURL.appendingPathComponent("listener/sing_tun/server.go")
    let tunnelSourceURL = goCoreRootURL.appendingPathComponent("tunnel/tunnel.go")
    let routeDecisionSourceURL = goCoreRootURL.appendingPathComponent("tunnel/route_decision.go")
    let routeDecisionControllerURL = goCoreRootURL.appendingPathComponent("hub/route/route_decisions.go")
    let routeServerURL = goCoreRootURL.appendingPathComponent("hub/route/server.go")
    let consoleViewModelSource = (try? String(contentsOf: consoleViewModelURL, encoding: .utf8)) ?? ""
    let consolePresentationDeriversSource = (try? String(contentsOf: consolePresentationDeriversURL, encoding: .utf8)) ?? ""
    let consoleRuntimeIOSource = (try? String(contentsOf: consoleRuntimeIOURL, encoding: .utf8)) ?? ""
    let consoleProxySelectionSource = (try? String(contentsOf: consoleProxySelectionURL, encoding: .utf8)) ?? ""
    let consoleDiagnosticsWriterSource = (try? String(contentsOf: consoleDiagnosticsWriterURL, encoding: .utf8)) ?? ""
    let consoleProxyDelayTestingSource = (try? String(contentsOf: consoleProxyDelayTestingURL, encoding: .utf8)) ?? ""
    let consoleProfileLibraryCoordinatorSource = (try? String(contentsOf: consoleProfileLibraryCoordinatorURL, encoding: .utf8)) ?? ""
    let runtimeModelsSource = (try? String(contentsOf: runtimeModelsURL, encoding: .utf8)) ?? ""
    let appPagesSource = (try? String(contentsOf: appPagesURL, encoding: .utf8)) ?? ""
    let appShellSource = (try? String(contentsOf: appShellURL, encoding: .utf8)) ?? ""
    let appDesignSystemSource = (try? String(contentsOf: appDesignSystemURL, encoding: .utf8)) ?? ""
    let contentViewSource = (try? String(contentsOf: contentViewURL, encoding: .utf8)) ?? ""
    let sharedStoreSource = (try? String(contentsOf: sharedStoreURL, encoding: .utf8)) ?? ""
    let compatibilityServiceSource = (try? String(contentsOf: compatibilityServiceURL, encoding: .utf8)) ?? ""
    let runtimeBridgeProtocolSource = (try? String(contentsOf: runtimeBridgeProtocolURL, encoding: .utf8)) ?? ""
    let runtimeBridgeSource = (try? String(contentsOf: runtimeBridgeURL, encoding: .utf8)) ?? ""
    let geoResourceManagerSource = (try? String(contentsOf: geoResourceManagerURL, encoding: .utf8)) ?? ""
    let packetTunnelProviderSource = (try? String(contentsOf: packetTunnelProviderURL, encoding: .utf8)) ?? ""
    let singTunServerSource = (try? String(contentsOf: singTunServerURL, encoding: .utf8)) ?? ""
    let tunnelSource = (try? String(contentsOf: tunnelSourceURL, encoding: .utf8)) ?? ""
    let routeDecisionSource = (try? String(contentsOf: routeDecisionSourceURL, encoding: .utf8)) ?? ""
    let routeDecisionControllerSource = (try? String(contentsOf: routeDecisionControllerURL, encoding: .utf8)) ?? ""
    let routeServerSource = (try? String(contentsOf: routeServerURL, encoding: .utf8)) ?? ""
    expect(!consoleViewModelSource.isEmpty, "default controlled config source should be readable")
    expect(!consolePresentationDeriversSource.isEmpty, "console presentation derivers source should be readable")
    expect(!consoleRuntimeIOSource.isEmpty, "console runtime IO source should be readable")
    expect(!consoleProxySelectionSource.isEmpty, "console proxy selection source should be readable")
    expect(!consoleDiagnosticsWriterSource.isEmpty, "console diagnostics writer source should be readable")
    expect(!consoleProxyDelayTestingSource.isEmpty, "console proxy delay testing source should be readable")
    expect(!consoleProfileLibraryCoordinatorSource.isEmpty, "console profile library coordinator source should be readable")
    expect(!runtimeModelsSource.isEmpty, "runtime models source should be readable")
    expect(!appPagesSource.isEmpty, "app pages source should be readable")
    expect(!appShellSource.isEmpty, "app shell source should be readable")
    expect(!appDesignSystemSource.isEmpty, "app design system source should be readable")
    expect(!contentViewSource.isEmpty, "content view source should be readable")
    expect(!sharedStoreSource.isEmpty, "shared store source should be readable")
    expect(!compatibilityServiceSource.isEmpty, "compatibility service source should be readable")
    expect(!runtimeBridgeSource.isEmpty, "runtime bridge source should be readable")
    expect(!geoResourceManagerSource.isEmpty, "geo resource manager source should be readable")
    expect(!packetTunnelProviderSource.isEmpty, "packet tunnel provider source should be readable")
    expect(!singTunServerSource.isEmpty, "mihomo sing-tun server source should be readable")
    expect(!tunnelSource.isEmpty, "mihomo tunnel source should be readable")
    expect(!routeDecisionSource.isEmpty, "mihomo route decision source should be readable")
    expect(!routeDecisionControllerSource.isEmpty, "mihomo route decision controller source should be readable")
    expect(!routeServerSource.isEmpty, "mihomo route server source should be readable")
    let sharedStoreDiagnostics = SharedStore.appGroupDiagnostics()
    expect(
      sharedStoreDiagnostics.appGroupIdentifier == SharedStore.appGroupIdentifier,
      "shared store diagnostics should report the configured App Group identifier"
    )
    expect(
      sharedStoreDiagnostics.isAvailable || !(sharedStoreDiagnostics.errorDescription ?? "").isEmpty,
      "shared store diagnostics should expose a concrete App Group access error instead of silently swallowing it"
    )
    expect(
      consoleViewModelSource.contains("SharedStore.appGroupDiagnostics()"),
      "console bootstrap should run an explicit App Group health check before VPN actions"
    )
    expect(
      consoleViewModelSource.contains("ConsoleDiagnosticsWriter.shared.writeSharedStoreDiagnostics")
        && consoleDiagnosticsWriterSource.contains("clashparty-shared-store-diagnostics.json"),
      "console bootstrap should mirror App Group health failures into the app sandbox for device debugging"
    )
    expect(
      consoleViewModelSource.contains("ConsoleDiagnosticsWriter.shared.writeRuntimeDiagnostics")
        && consoleDiagnosticsWriterSource.contains("clashparty-runtime-diagnostics.json"),
      "console runtime refresh should mirror status and logs into the app sandbox for device debugging"
    )
    expect(
      consoleDiagnosticsWriterSource.contains("DispatchQueue(")
        && consoleDiagnosticsWriterSource.contains("writeRuntimeDiagnosticsToAppSandbox")
        && !consoleViewModelSource.contains("writeRuntimeDiagnosticsToAppSandbox"),
      "console runtime refresh should hand app-sandbox diagnostics to a background writer instead of doing JSON file IO on the main actor"
    )
    expect(
      contentViewSource.contains("--codex-auto-start-tunnel"),
      "debug automation should be able to launch the app and trigger one VPN start without manual tapping"
    )
    expect(
      sharedStoreSource.contains("shared-store-health.json"),
      "shared store diagnostics should write a visible marker into the App Group runtime directory"
    )
    expect(
      sharedStoreSource.contains("limit: Int = 1200"),
      "shared runtime logs should retain enough entries to preserve startup diagnostics during noisy failed tunnels"
    )
    expect(
      sharedStoreSource.contains("pendingLogEntries"),
      "packet tunnel logs should be batched before touching shared JSON storage to avoid a per-log encode/write CPU loop"
    )
    expect(
      sharedStoreSource.contains("scheduleLogFlush"),
      "packet tunnel log writes should coalesce bursts instead of rewriting the log file for every debug entry"
    )
    expect(
      sharedStoreSource.contains("encoder.dateEncodingStrategy = .iso8601"),
      "shared store persistence should keep machine-readable UTC dates on the hot path"
    )
    expect(
      !sharedStoreSource.contains("encoder.dateEncodingStrategy = .custom"),
      "shared store persistence must not create per-date local formatters while the packet tunnel is appending logs"
    )
    expect(
      consoleViewModelSource.contains("formattedLogTimestamp"),
      "logs UI should use an explicit local timestamp formatter instead of an ambiguous default time-only format"
    )
    expect(
      consoleViewModelSource.contains("static let logTimestampFormatter"),
      "logs UI should reuse one DateFormatter instead of allocating a formatter for every rendered log row"
    )
    expect(
      !consoleViewModelSource.contains("func formattedLogTimestamp(_ timestamp: Date) -> String {\n    let formatter = DateFormatter()"),
      "logs UI must not allocate DateFormatter inside formattedLogTimestamp because SwiftUI can call it repeatedly while rendering"
    )
    expect(
      consoleViewModelSource.contains("runtimeDiagnosticsWriteInterval"),
      "app-sandbox runtime diagnostics export should be throttled instead of rewriting the full snapshot on every foreground poll"
    )
    expect(
      appDesignSystemSource.contains("struct StatusInfoChip"),
      "home should have a compact status chip component for first-screen connection context"
    )
    expect(
      appDesignSystemSource.contains("AppPalette.parchment")
        && appDesignSystemSource.contains("static let accent = Color(uiColor: .systemBlue)")
        && appDesignSystemSource.contains("static let canvas = Color(uiColor: .secondarySystemGroupedBackground)")
        && appDesignSystemSource.contains("static let pearl = Color(uiColor: .tertiarySystemGroupedBackground)"),
      "Apple-style app UI should use iOS semantic grouped colors instead of hard-coded marketing-page tokens"
    )
    expect(
      appDesignSystemSource.contains("struct ApplePrimaryButtonStyle")
        && appDesignSystemSource.contains("struct AppleSecondaryButtonStyle")
        && appDesignSystemSource.contains("struct AppleUtilityButtonStyle")
        && appDesignSystemSource.contains("func appleTextField() -> some View"),
      "Apple-style buttons and text fields should be centralized in the design system"
    )
    expect(
      !appDesignSystemSource.contains("LinearGradient(")
        && !appPagesSource.contains(".buttonStyle(.bordered")
        && !appPagesSource.contains(".buttonStyle(.borderedProminent")
        && !appPagesSource.contains(".textFieldStyle(.roundedBorder"),
      "Apple-style pages should avoid decorative gradients, default bordered buttons, and roundedBorder text fields"
    )
    expect(
      appPagesSource.contains("overview.plan.title") && appPagesSource.contains("\"Connection Plan\""),
      "home should lead with a connection plan instead of a generic quick-actions section"
    )
    expect(
      !appPagesSource.contains("\"Proxy Command Center\""),
      "node page copy should avoid desktop-style command-center language"
    )
    expect(
      appPagesSource.contains("displayedLogs = Array(viewModel.logs.suffix(40))"),
      "logs page should materialize the rendered log window once per body pass"
    )
    expect(
      appPagesSource.contains("ProfileLibraryRow")
        && appPagesSource.contains("BackupListRow")
        && appPagesSource.contains("RulePreviewRow")
        && appPagesSource.contains("ConnectionListRow")
        && appPagesSource.contains("ResourceListRow")
        && appPagesSource.contains("LogListRow"),
      "data-heavy pages should use compact grouped list rows instead of ad hoc card stacks"
    )
    expect(
      appPagesSource.contains("Paste & Download"),
      "remote subscription copy should describe the combined paste/download action instead of the vague paste/import wording"
    )
    expect(
      appPagesSource.contains("remotePrimaryActionTitle") && appPagesSource.contains("remoteProfileURLIsBlank"),
      "remote subscription import should expose one primary action that adapts to whether a URL is already entered"
    )
    expect(
      !appPagesSource.contains("remoteActionColumns"),
      "remote subscription actions should not regress to an equal-weight multi-button grid on compact iPhone layouts"
    )
    expect(
      appPagesSource.contains(".accessibilityLabel(L10n.string(\"profiles.remote.paste\""),
      "remote subscription paste should stay attached to the URL field with an accessible label instead of becoming another competing full-width action"
    )
    expect(
      runtimeModelsSource.contains("struct RouteExplanation") && runtimeModelsSource.contains("enum RouteExplanationResolver"),
      "rule insight should use a pure route explanation model instead of burying explanation logic inside SwiftUI rendering"
    )
    expect(
      runtimeModelsSource.contains("chainComponents: [String]") && runtimeModelsSource.contains("displayOptions: [String]"),
      "runtime snapshots should carry pre-derived route chains and proxy display options so SwiftUI does not repeatedly split or dedupe hot lists"
    )
    expect(
      consoleViewModelSource.contains("@Published private(set) var displayedProxyGroups")
        && consoleViewModelSource.contains("@Published private(set) var routeExplanations"),
      "console view model should publish derived proxy groups and route explanations instead of recomputing them inside SwiftUI bodies"
    )
    expect(
      consoleRuntimeIOSource.contains("struct RuntimeCacheFingerprint")
        && consoleRuntimeIOSource.contains("static func directory(at url: URL)")
        && consoleRuntimeIOSource.contains("itemURL.lastPathComponent"),
      "console runtime IO cache should fingerprint directory contents by name/mtime/size so backup deletion or rename invalidates the cached list"
    )
    expect(
      consolePresentationDeriversSource.contains("struct RouteExplanationInput")
        && consolePresentationDeriversSource.contains("lastInput")
        && consolePresentationDeriversSource.contains("let persistedExplanations = sourceConnections.isEmpty ? lastPersistedExplanations : []")
        && !consolePresentationDeriversSource.contains("SharedStore.readRouteExplanations()")
        && consoleViewModelSource.contains("rebuildRouteExplanationsIfNeeded"),
      "console view model should cache route explanation inputs and reuse seeded persisted explanations instead of reading route explanation JSON during empty live-connection refreshes"
    )
    expect(
      consoleProxySelectionSource.contains("struct ProxySelectionRuntimeState")
        && consoleProxySelectionSource.contains("struct ProxySelectionCoordinator")
        && consoleProxySelectionSource.contains("var nextPendingRequest: ProxySelectionRequest?"),
      "proxy selection runtime state, validation, materialization, and overrides should be centralized instead of spread across the console view model"
    )
    expect(
      consoleRuntimeIOSource.contains("enum ConsoleRuntimeSnapshotScope")
        && consoleRuntimeIOSource.contains("scope: ConsoleRuntimeSnapshotScope")
        && consoleViewModelSource.contains("await self.syncSystemTunnelStatus(scope: .fast)")
        && consoleViewModelSource.contains("snapshot.logs ?? SharedStore.readLogs()"),
      "controller snapshot polling should keep a fast data-plane path separate from full logs/profile/proxy-group hydration"
    )
    expect(
      consoleRuntimeIOSource.contains("runtime-snapshot-io")
        && consoleRuntimeIOSource.contains("runtime-control-io")
        && consoleRuntimeIOSource.contains("runtime-delay-io")
        && consoleRuntimeIOSource.contains("private let snapshotRuntime: RuntimeBridge")
        && consoleRuntimeIOSource.contains("private let controlRuntime: RuntimeBridge")
        && consoleRuntimeIOSource.contains("private let delayRuntime: RuntimeBridge")
        && consoleRuntimeIOSource.contains("controlRuntime = RuntimeBridgeFactory.makeAppBridge()")
        && consoleRuntimeIOSource.contains("delayRuntime = RuntimeBridgeFactory.makeAppBridge()")
        && !consoleRuntimeIOSource.contains("org.mihomo.party.ios.console.runtime-io"),
      "console runtime IO should isolate snapshot refresh, control actions, and long-running delay tests with separate queues and bridge instances so speed tests cannot block the UI refresh path or race snapshot throttling state"
    )
    expect(
      consoleProxyDelayTestingSource.contains("struct ProxyDelayTestingState")
        && consoleViewModelSource.contains("private var proxyDelayTestingState = ProxyDelayTestingState()")
        && consoleViewModelSource.contains("beginProxyGroupDelayTest")
        && !consoleViewModelSource.contains("measureProxyDelaysIndividually"),
      "proxy delay testing state should be centralized outside the view model instead of scattering in-flight groups, per-node statuses, and unused fallback probes"
    )
    expect(
      consoleProfileLibraryCoordinatorSource.contains("org.mihomo.party.ios.console.profile-library")
        && consoleProfileLibraryCoordinatorSource.contains("SharedStore.saveProfileRecord")
        && consoleProfileLibraryCoordinatorSource.contains("SharedStore.deleteProfileRecord")
        && consoleProfileLibraryCoordinatorSource.contains("SharedStore.createBackupRecord")
        && consoleProfileLibraryCoordinatorSource.contains("SharedStore.exportCurrentBundle")
        && consoleViewModelSource.contains("private let profileLibraryCoordinator = ConsoleProfileLibraryCoordinator()")
        && consoleViewModelSource.contains("try await profileLibraryCoordinator.saveProfile")
        && consoleViewModelSource.contains("try await profileLibraryCoordinator.exportCurrentBundle")
        && !consoleViewModelSource.contains("try SharedStore.saveProfileRecord(record)")
        && !consoleViewModelSource.contains("try SharedStore.exportCurrentBundle("),
      "profile library, backup, and export file IO should run through a background coordinator instead of blocking the main view model actor"
    )
    expect(
      appPagesSource.contains("ForEach(sortedOptions.indices, id: \\.self)")
        && !appPagesSource.contains("var seen = Set<String>()\n    return group.all.filter"),
      "proxy group detail should render pre-deduped and sorted display options instead of rebuilding a Set in the view body"
    )
    expect(
      appPagesSource.contains("struct ProxyOptionRow")
        && !appPagesSource.contains("ScrollView(.horizontal, showsIndicators: false)")
        && appPagesSource.contains("ProxyGroupSummaryStrip"),
      "proxy group detail should use a summary strip plus vertical node rows instead of cramped horizontal option chips"
    )
    expect(
      appDesignSystemSource.contains("struct AppGroupedList")
        && appDesignSystemSource.contains("struct AppNavigationListRow")
        && appDesignSystemSource.contains("struct AppPageHeader")
        && appDesignSystemSource.contains("struct AppLayoutMetrics")
        && appDesignSystemSource.contains("GeometryReader")
        && appPagesSource.contains("remoteURLInputRow")
        && appPagesSource.contains("RouteFactPill")
        && appPagesSource.contains("RuleInsightDetailRow"),
      "Apple-style pages should use native grouped lists, dynamic page metrics, integrated subscription URL input, and structured route insight details"
    )
    expect(
      appDesignSystemSource.contains("appLayoutMetrics")
        && appPagesSource.contains("layoutMetrics.flexibleColumns(minimum: 168")
        && appPagesSource.contains("layoutMetrics.flexibleColumns(minimum: 158")
        && appPagesSource.contains("ViewThatFits(in: .horizontal)"),
      "phone layouts should adapt to real available width instead of relying on fixed iPhone-sized grids"
    )
    expect(
      consoleViewModelSource.contains("func proxyGroupDisplaySelection(for group: ProxyGroupSnapshot) -> String"),
      "proxy group detail should render the effective display selection so queued/offline preferences do not look like a stale selected node"
    )
    expect(
      consolePresentationDeriversSource.contains("enum ProxyNodeSortMode")
        && consoleViewModelSource.contains("@Published var proxyNodeSortMode")
        && consoleViewModelSource.contains("func sortedProxyOptions(for group: ProxyGroupSnapshot) -> [String]")
        && appPagesSource.contains("ProxyNodeSortControl(selection: sortModeBinding)")
        && appPagesSource.contains("set: { viewModel.proxyNodeSortMode = $0 }"),
      "proxy nodes should expose a shared latency sort mode for group detail and subscription node lists"
    )
    expect(
      consolePresentationDeriversSource.contains("CachedSortedProxyOptions")
        && consolePresentationDeriversSource.contains("sortedOptionsCache")
        && consolePresentationDeriversSource.contains("relevantDelayStatuses(for: group.displayOptions")
        && consoleViewModelSource.contains("cachedAppDelayTestSettings"),
      "proxy pages should cache sorted group options and parsed delay-test settings instead of recomputing them during SwiftUI body updates"
    )
    expect(
      appPagesSource.contains("private var leadingIcon: String")
        && appPagesSource.contains("return allowsSelection ? \"circle\" : \"lock.circle\"")
        && appPagesSource.contains("AppPalette.accentSoft")
        && appPagesSource.contains("private struct ProxyNodeSurface"),
      "proxy node rows should clearly separate selected, selectable, and runtime-locked states without greying the whole list"
    )
    expect(
      appPagesSource.contains("ProxyNodeSortControl(selection: sortModeBinding)")
        && appPagesSource.contains("ProxyNodeSortControl(selection: $sortMode)")
        && appPagesSource.contains("L10n.string(\"proxies.sort.title\", \"Sort\")"),
      "latency sorting should be visible on both the group detail and subscription node lists"
    )
    expect(
      consolePresentationDeriversSource.contains("struct ProxyPresentationState")
        && consolePresentationDeriversSource.contains("final class ProxyPresentationModel")
        && consoleViewModelSource.contains("refreshProxyPresentation()")
        && appPagesSource.contains("@ObservedObject private var presentation: ProxyPresentationModel")
        && appPagesSource.contains("let viewModel: ConsoleViewModel")
        && appPagesSource.contains("presentation.state.displayedGroups")
        && appPagesSource.contains("presentation.state.displayedNodes"),
      "proxy pages should observe a narrow presentation model so logs, traffic, and unrelated console state do not redraw large node lists"
    )
    expect(
      appShellSource.contains("case ruleInsight") && appShellSource.contains("RuleInsightPage(viewModel: viewModel)"),
      "More navigation should expose a dedicated Rule Insight management page"
    )
    expect(
      appShellSource.contains("primaryMoreDestinations")
        && appShellSource.contains("diagnosticMoreDestinations")
        && appShellSource.contains("advancedMoreDestinations")
        && appPagesSource.contains("MoreDestinationSection"),
      "iPad sidebar and More hub should share the Primary / Diagnostics / Advanced operation model"
    )
    expect(
      consolePresentationDeriversSource.contains("struct RuleInsightPresentationState")
        && consolePresentationDeriversSource.contains("final class RuleInsightPresentationModel")
        && consoleViewModelSource.contains("refreshRuleInsightPresentation()")
        && consoleViewModelSource.contains("usingRecentSnapshot")
        && consolePresentationDeriversSource.contains("recentConnections")
        && appPagesSource.contains("struct RuleInsightPage")
        && appPagesSource.contains("@ObservedObject private var presentation: RuleInsightPresentationModel")
        && appPagesSource.contains("let explanations = state.explanations")
        && appPagesSource.contains("rule_insight.recent_snapshot_notice"),
      "rule insight page should render precomputed route explanations from the view model and preserve the most recent controller-backed decisions when live connections briefly disappear"
    )
    expect(
      runtimeBridgeProtocolSource.contains("func refreshSnapshotNow()")
        && consoleViewModelSource.contains("forceControllerSnapshotRefresh")
        && consoleRuntimeIOSource.contains("cachedDataPlaneSnapshotValue(")
        && consoleRuntimeIOSource.contains("cachedConnectionsValue(forceReload: forceReload)")
        && consoleViewModelSource.contains("noteEmptyRouteInsightSnapshotIfNeeded")
        && consoleRuntimeIOSource.contains("persistedTrafficIsStale")
        && appPagesSource.contains("RuleInsightSnapshotHint")
        && appPagesSource.contains("rule_insight.hint.app_group"),
      "rule insight refresh should force a controller snapshot, bypass stale connection cache, avoid stale traffic snapshots, and expose App Group/controller diagnostics when empty"
    )
    expect(
      !appPagesSource.contains("RouteExplanationResolver.explain(displayedConnections)"),
      "rule insight page must not recompute route explanations inside the SwiftUI body"
    )
    expect(
      appPagesSource.contains("rule_insight.card.dns_context")
        && appPagesSource.contains("rule_insight.card.rule_type")
        && appPagesSource.contains("rule_insight.card.destination_asn")
        && runtimeModelsSource.contains("enum DNSContext")
        && runtimeModelsSource.contains("enum RuleKind")
        && runtimeModelsSource.contains("public var sniffHost: String")
        && runtimeBridgeSource.contains("metadata.sniffHost")
        && runtimeBridgeSource.contains("\\($0.metadata.sniffHost)")
        && runtimeModelsSource.contains("connection.metadata.sniffHost"),
      "rule insight page should render structured rule/DNS/ASN explanation fields instead of reconstructing explanation prose in SwiftUI"
    )
    expect(
      consoleDiagnosticsWriterSource.contains("localDiagnosticsDateEncodingStrategy"),
      "app-sandbox diagnostics should encode exported timestamps with the user's local timezone"
    )
    expect(
      consoleDiagnosticsWriterSource.contains("TimeZone.autoupdatingCurrent"),
      "app-sandbox diagnostics should follow the device's current timezone when writing human-readable timestamps"
    )
    expect(
      runtimeBridgeSource.contains("if role == .packetTunnel")
        && runtimeBridgeSource.contains("startPacketTunnelFastSnapshotPolling()")
        && runtimeBridgeSource.contains("return\n    }\n\n    appendLog(level: \"debug\", message: \"Starting controller observers")
        && runtimeBridgeSource.contains("startObservers(with: activatedMetadata)"),
      "packet tunnel should avoid long-lived log and traffic observers while still allowing app role controller observers"
    )
    expect(
      runtimeBridgeSource.contains("System VPN is active, so the app is starting a lightweight delay-test core without tun")
        && !runtimeBridgeSource.contains("Skipped the app-side offline delay-test core"),
      "node delay tests should not measure through the live Packet Tunnel controller when the system VPN is active"
    )
    expect(
      runtimeBridgeSource.contains("perProxyDelayWorkerCount(proxyCount:)")
        && runtimeBridgeSource.contains("ProcessInfo.processInfo.activeProcessorCount")
        && runtimeBridgeSource.contains("workerCount = perProxyDelayWorkerCount(proxyCount: proxyNames.count)")
        && runtimeBridgeSource.contains("runtime-delay-probes"),
      "per-proxy delay fallback should derive bounded worker count from device parallelism instead of a fixed magic concurrency limit"
    )
    expect(
      !runtimeBridgeSource.contains("maxConcurrentPerProxyDelayRequests = 8"),
      "per-proxy delay fallback should not regress to the old fixed eight-worker magic limit"
    )
    expect(
      runtimeBridgeSource.contains("buildDelayTestRuntimeConfig(\n      fromRuntimeConfig: configurationBundle.runtimeConfig")
        && compatibilityServiceSource.contains("buildDelayTestRuntimeConfig(fromRuntimeConfig runtimeConfig: String)"),
      "VPN-active node delay tests should preserve Packet Tunnel injected proxy host overrides by deriving the lightweight core from the published runtime config"
    )
    expect(
      runtimeBridgeSource.contains("GeoResourceManager.seedBundledResourcesIfNeeded(\n      from: configurationBundle.runtimeConfig")
        && runtimeBridgeSource.contains("GeoResourceManager.seedBundledResourcesIfNeeded(\n      from: runtimeConfig,\n      homeURL: homeDirectoryURL")
        && geoResourceManagerSource.contains("persistRuntimeStatus: false"),
      "packet tunnel startup/reload and lightweight delay-test cores should seed bundled MetaCubeX route databases before starting without polluting global resource status from temporary homes"
    )
    expect(
      runtimeBridgeSource.contains("Packet Tunnel started lightweight controller snapshot polling so background browser traffic keeps route diagnostics fresh without attaching long-lived log streams.")
        && runtimeBridgeSource.contains("startPacketTunnelFastSnapshotPolling()")
        && !runtimeBridgeSource.contains("startObservers(with: activatedMetadata)\n      return"),
      "packet tunnel should keep only lightweight fast snapshot polling for route diagnostics without restoring long-lived log or traffic observers"
    )
    expect(
      runtimeBridgeSource.contains("controllerRequestQueue")
        && runtimeBridgeSource.contains("func fetchFastControllerPayload")
        && runtimeBridgeSource.contains("ControllerFastPayloadResults")
        && runtimeBridgeSource.contains("group.wait()"),
      "app-side controller fast snapshots should fetch runtime status and connections in parallel with synchronized result handoff"
    )
    expect(
      runtimeModelsSource.contains("struct RouteDecisionSnapshot")
        && runtimeModelsSource.contains("public static func explain(_ decision: RouteDecisionSnapshot)")
        && runtimeModelsSource.contains("public static func explain(_ decisions: [RouteDecisionSnapshot])")
        && runtimeBridgeSource.contains("routeDecisions: [RouteDecisionSnapshot]")
        && runtimeBridgeSource.contains("try client.fetchRouteDecisions()")
        && runtimeBridgeSource.contains("RouteExplanationResolver.explain(recentRouteDecisions)")
        && runtimeBridgeSource.contains("routeExplanationSignature(routeDecisions:")
        && routeDecisionControllerSource.contains("func getRouteDecisions")
        && routeDecisionControllerSource.contains("tunnel.RouteDecisions()")
        && routeServerSource.contains("r.Get(\"/route-decisions\", getRouteDecisions)"),
      "rule insight should consume controller-backed structured route decisions before falling back to inferred connection chains"
    )
    expect(
      routeDecisionSource.contains("func routeDecisionCapacity()")
        && routeDecisionSource.contains("cap(tcpQueue)")
        && routeDecisionSource.contains("cap(udpQueue)")
        && routeDecisionSource.contains("func recordRouteDecision(")
        && !routeDecisionSource.contains("make([]RouteDecision, 0, 200)"),
      "route decision retention should be derived from tunnel queue capacity instead of adding another fixed ring-size magic value"
    )
    expect(
      runtimeBridgeSource.contains("ControllerSlowPayloadResults")
        && runtimeBridgeSource.contains("func fetchSlowControllerPayload")
        && runtimeBridgeSource.contains("results.setProxyGroups(Result")
        && runtimeBridgeSource.contains("results.setVersion(Result"),
      "app-side controller slow snapshots should fetch proxy groups and controller version in parallel instead of serializing the slow path"
    )
    expect(
      tunnelSource.contains("iosTunDialRetryAttempts")
        && tunnelSource.contains("= 3")
        && tunnelSource.contains("iosTunDialRetryMaxWait")
        && tunnelSource.contains("120 * time.Millisecond")
        && tunnelSource.contains("retry(ctx, metadata")
        && tunnelSource.contains("if i == maxAttempts-1")
        && tunnelSource.contains("retryAfter(b.Duration())")
        && tunnelSource.contains("dialRetryMaxWait(metadata)")
        && tunnelSource.contains("func dialRetryAttempts(metadata *C.Metadata) int"),
      "iOS TUN dial retries should use a short interactive budget, bounded backoff, and skip sleeping after the final failed attempt"
    )
    expect(
      packetTunnelProviderSource.contains("makePacketTunnelNetworkPlan(from: runtimeConfig)"),
      "packet tunnel network settings should be derived from the final sanitized runtime config"
    )
    expect(
      !packetTunnelProviderSource.contains("198.18.0.0"),
      "packet tunnel must not hard-code a legacy 198.18/16 route exclusion because proxy-server DNS answers are subscription-specific"
    )
    expect(
      packetTunnelProviderSource.contains("resolveProxyServerHostRouteExclusions"),
      "packet tunnel should derive route exclusions from resolved proxy server hostnames"
    )
    expect(
      packetTunnelProviderSource.contains("extractBootstrapDNSEndpointHosts"),
      "packet tunnel should also derive route exclusions from configured bootstrap DNS IP endpoints"
    )
    expect(
      packetTunnelProviderSource.contains("resolveNumericAddresses(for: endpoint, nameservers: bootstrapDNSAddresses)"),
      "packet tunnel should resolve proxy server route exclusions through configured bootstrap DNS before falling back to system DNS"
    )
    expect(
      packetTunnelProviderSource.contains("injectingResolvedProxyServerHosts"),
      "packet tunnel should inject dynamically resolved proxy server host overrides before starting the embedded core"
    )
    expect(
      packetTunnelProviderSource.contains("writeBootstrappedRuntimeConfigIfNeeded"),
      "packet tunnel should persist the bootstrapped runtime config at the path passed to MihomoStart"
    )
    expect(
      singTunServerSource.contains("sing_tun.New is flushing the initial default interface after the monitor start."),
      "iOS tun startup should actively bind outbound dials to the physical default interface instead of waiting for a later network update callback"
    )
    expect(
      singTunServerSource.contains("returned tunnel-like interface"),
      "iOS default interface detection must reject utun/tunnel-like interfaces to avoid routing proxy dials back into the Packet Tunnel"
    )
    expect(
      singTunServerSource.contains("fallback physical interface"),
      "iOS default interface detection should fall back to a physical interface candidate when the monitor reports only tunnel-like interfaces"
    )
    expect(
      !consoleViewModelSource.contains("proxy-server-nameserver:\n      - https://dns.alidns.com/dns-query"),
      "default controlled config must not use hostname DoH for proxy-server bootstrap DNS"
    )
    expect(
      consoleViewModelSource.contains("proxy-server-nameserver:\n      - 223.5.5.5\n      - 119.29.29.29"),
      "default controlled config should use direct IP proxy-server bootstrap DNS"
    )
    expect(
      consoleViewModelSource.contains("fake-ip-range: 198.19.0.1/16"),
      "default controlled config should avoid the 198.18/16 fake-ip range because some proxy server domains resolve to 198.18.x.x endpoints"
    )
    expect(
      consoleViewModelSource.contains("geodata-mode: false"),
      "default controlled config should prefer bundled MMDB/dat resources without requiring startup geodata conversion"
    )
    expect(
      consoleViewModelSource.contains("default-nameserver:\n      - 223.5.5.5\n      - 119.29.29.29"),
      "default controlled config should provide direct IP fallback bootstrap DNS"
    )
    expect(
      consoleViewModelSource.contains("fallback-filter:\n      geoip: false"),
      "default controlled config should disable DNS fallback GeoIP to avoid MMDB-dependent startup"
    )
    let runtimeConfigWithLegacyBootstrapDNS = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileYAML,
        controlledConfigYaml: """
        mode: rule
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          nameserver:
            - https://dns.alidns.com/dns-query
          proxy-server-nameserver:
            - https://dns.alidns.com/dns-query
          fallback:
            - https://1.1.1.1/dns-query
          fallback-filter:
            geoip: true
        """,
        appConfigJson: "{}"
      )
    )
    expect(
      !runtimeConfigWithLegacyBootstrapDNS.contains("proxy-server-nameserver:\n    - https://dns.alidns.com/dns-query"),
      "runtime config should strip legacy hostname DoH proxy bootstrap DNS"
    )
    expect(
      !runtimeConfigWithLegacyBootstrapDNS.contains("https://dns.alidns.com/dns-query"),
      "runtime config should strip legacy hostname DoH nameservers so DNS bootstrap does not depend on the proxy tunnel"
    )
    expect(
      !runtimeConfigWithLegacyBootstrapDNS.contains("fallback:\n    - https://1.1.1.1/dns-query"),
      "runtime config should strip legacy fallback DoH during iOS bootstrap and rely on direct IP literal resolvers"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("fake-ip-range: 198.18.0.1/16"),
      "runtime config should preserve the user/subscription fake-ip range instead of replacing it with a fixed magic range"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("inet4-address:\n    - 172.31.255.1/30"),
      "runtime config should write the dynamically selected iOS tun IPv4 link address instead of deriving it from the fake-ip pool"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("geodata-mode: false"),
      "runtime config should explicitly keep the mobile route database mode aligned with bundled MMDB/dat resources"
    )
    let networkPlanFromSanitizedRuntime = compatibilityService.makePacketTunnelNetworkPlan(from: runtimeConfigWithLegacyBootstrapDNS)
    expect(
      networkPlanFromSanitizedRuntime.tunnelRemoteAddress == "172.31.255.2",
      "packet tunnel plan derived from sanitized runtime config should keep the tunnel peer outside the fake-ip pool"
    )
    expect(
      networkPlanFromSanitizedRuntime.ipv4Address == "172.31.255.1",
      "packet tunnel plan derived from sanitized runtime config should keep the local address outside the fake-ip pool"
    )
    expect(
      networkPlanFromSanitizedRuntime.dnsServers == ["172.31.255.2"],
      "packet tunnel DNS should use the tunnel peer rather than an address from the fake-ip pool"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("nameserver:\n    - 223.5.5.5\n    - 119.29.29.29"),
      "runtime config should install direct IP literal nameservers for iOS bootstrap"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("proxy-server-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29"),
      "runtime config should install direct IP proxy bootstrap DNS for legacy saved profiles"
    )
    expect(
      runtimeConfigWithLegacyBootstrapDNS.contains("default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29"),
      "runtime config should install direct IP default bootstrap DNS for legacy saved profiles"
    )
    expect(
      !runtimeConfigWithLegacyBootstrapDNS.contains("geoip: true"),
      "runtime config should disable inherited fallback-filter GeoIP for legacy saved profiles"
    )

    let runtimeConfigWithCustomTunAddress = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileYAML,
        controlledConfigYaml: """
        mode: rule
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
        tun:
          enable: true
          inet4-address:
            - 10.10.10.1/30
        """,
        appConfigJson: "{}"
      )
    )
    expect(
      runtimeConfigWithCustomTunAddress.contains("inet4-address:\n    - 10.10.10.1/30"),
      "runtime config should preserve an explicit non-overlapping tun.inet4-address"
    )

    let runtimeConfigWithConflictingTunAddress = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: profileYAML,
        controlledConfigYaml: """
        mode: rule
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 10.10.10.0/24
        tun:
          enable: true
          inet4-address:
            - 10.10.10.1/30
        """,
        appConfigJson: "{}"
      )
    )
    expect(
      runtimeConfigWithConflictingTunAddress.contains("inet4-address:\n    - 172.31.255.1/30"),
      "runtime config should replace only a tun.inet4-address that overlaps the configured fake-ip range"
    )

    let routedSubscriptionProfile = """
    proxies:
      - name: 🇭🇰香港01A
        type: trojan
        server: okanc.iepl.cac.cab
        port: 30401
      - { name: 🇭🇰香港01B, type: trojan, server: okanc.direct.cac.cab, port: 41116 }
    proxy-groups:
      - name: 🍎 苹果服务
        type: select
        proxies:
          - DIRECT
          - 🇭🇰香港01A
      - name: 🚀 节点选择
        type: select
        proxies:
          - 🇭🇰香港01A
          - 🇭🇰香港01B
      - name: 🌍 国外媒体
        type: select
        proxies:
          - 🚀 节点选择
          - DIRECT
      - name: 🐟 漏网之鱼
        type: select
        proxies:
          - 🚀 节点选择
          - DIRECT
    rule-providers:
      google:
        type: http
        behavior: domain
        url: https://rules.example.org/google.yaml
        path: ./providers/google.yaml
        interval: 86400
    rules:
      - GEOSITE,cn,DIRECT
      - DOMAIN-SUFFIX,apple.com,🍎 苹果服务
      - RULE-SET,google,🚀 节点选择
      - MATCH,🐟 漏网之鱼
    """
    let routedRuntimeConfig = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: routedSubscriptionProfile,
        controlledConfigYaml: """
        mode: rule
        dns:
          enable: true
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          fake-ip-filter:
            - "*.lan"
            - "*.local"
          nameserver:
            - 223.5.5.5
            - 119.29.29.29
          proxy-server-nameserver:
            - 223.5.5.5
            - 119.29.29.29
          default-nameserver:
            - 223.5.5.5
            - 119.29.29.29
          fallback-filter:
            geoip: false
        """,
        appConfigJson: "{}"
      )
    )
    expect(
      routedRuntimeConfig.contains("DOMAIN-SUFFIX,apple.com,🍎 苹果服务"),
      "runtime config should preserve imported subscription rules before the final MATCH fallback"
    )
    expect(
      routedRuntimeConfig.contains("RULE-SET,google,🚀 节点选择"),
      "runtime config should preserve imported RULE-SET routing targets instead of collapsing traffic to MATCH"
    )
    let routedRuntimeLines = routedRuntimeConfig
      .components(separatedBy: .newlines)
      .map { $0.trimmingCharacters(in: .whitespaces) }
    func firstRuntimeRuleIndex(_ rule: String) -> Int {
      routedRuntimeLines.firstIndex(of: "- \(rule)") ?? Int.max
    }
    expect(
      routedRuntimeConfig.contains("sniffer:\n  enable: true")
        && routedRuntimeConfig.contains("force-dns-mapping: true")
        && routedRuntimeConfig.contains("parse-pure-ip: true")
        && routedRuntimeConfig.contains("TLS:\n      ports:\n        - 443")
        && routedRuntimeConfig.contains("HTTP:\n      ports:\n        - 80"),
      "iOS runtime config should enable protocol-level metadata attribution instead of relying on app-specific platform rules"
    )
    expect(
      firstRuntimeRuleIndex("GEOSITE,cn,DIRECT") < firstRuntimeRuleIndex("MATCH,🐟 漏网之鱼"),
      "imported broad CN/DIRECT rules should remain before the final MATCH fallback"
    )
    expect(
      !routedRuntimeConfig.contains("DOMAIN-SUFFIX,tiktokv.com")
        && !routedRuntimeConfig.contains("DOMAIN-SUFFIX,byteoversea.com")
        && !routedRuntimeConfig.contains("DOMAIN-SUFFIX,muscdn.com")
        && !routedRuntimeConfig.contains("# iOS platform priority rules"),
      "compatibility generation must not invent hard-coded platform domain rules; platform routing should come from subscription rules, GeoSite, Fake DNS, or sniffed metadata"
    )
    let platformFallbackRuntimeConfig = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: """
        proxies:
          - name: HK
            type: socks5
            server: 127.0.0.1
            port: 1080
        proxy-groups:
          - name: 🚀 节点选择
            type: select
            proxies:
              - HK
              - DIRECT
          - name: 🎯 全球直连
            type: select
            proxies:
              - DIRECT
        rules:
          - GEOIP,CN,🎯 全球直连,no-resolve
          - MATCH,🚀 节点选择
        """,
        controlledConfigYaml: "mode: rule",
        appConfigJson: "{}"
      )
    )
    expect(
      !platformFallbackRuntimeConfig.contains("DOMAIN-SUFFIX,tiktokv.com")
        && platformFallbackRuntimeConfig.contains("sniffer:\n  enable: true"),
      "runtime config should not add platform fallback domain rules when no subscription rule exists; it should keep generic metadata attribution enabled"
    )
    expect(
      routedRuntimeConfig.contains("asn: https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"),
      "runtime config should keep the MetaCubeX ASN database available for explicit IP-ASN rules and route explanations"
    )
    expect(
      !routedRuntimeConfig.contains("# iOS ASN enhancement runs after domain/GeoIP rules and before the final MATCH fallback.")
        && !routedRuntimeConfig.contains("IP-ASN,4134,DIRECT,no-resolve"),
      "runtime config should not inject default ASN routing rules because they can override subscription policy or break older embedded cores"
    )
    expect(
      routedRuntimeConfig.contains("rule-providers:\n  google:"),
      "runtime config should preserve imported rule providers so RULE-SET rules can become active"
    )
    expect(
      routedRuntimeConfig.contains("    - okanc.iepl.cac.cab"),
      "runtime config should add inline proxy server hostnames to dns.fake-ip-filter so proxy bootstrap never dials Fake IPs"
    )
    expect(
      routedRuntimeConfig.contains("    - okanc.direct.cac.cab"),
      "runtime config should add inline object proxy server hostnames to dns.fake-ip-filter"
    )
    let runtimeConfigWithResolvedProxyHosts = compatibilityService.injectingResolvedProxyServerHosts(
      in: routedRuntimeConfig,
      resolvedHosts: [
        "okanc.iepl.cac.cab": ["203.0.113.7"],
        "okanc.direct.cac.cab": ["2001:db8::7"]
      ]
    )
    expect(
      runtimeConfigWithResolvedProxyHosts.contains("hosts:\n  okanc.direct.cac.cab: 2001:db8::7\n  okanc.iepl.cac.cab: 203.0.113.7"),
      "runtime config should inject dynamically resolved proxy server host overrides before the embedded core starts"
    )
    expect(
      !runtimeConfigWithResolvedProxyHosts.contains("198.18.0.0/16"),
      "resolved proxy server host injection must not rely on fixed 198/16 magic route assumptions"
    )
    let runtimeConfigWithExistingASN = compatibilityService.buildRuntimeConfig(
      from: CompatibilityInput(
        profileYaml: """
        proxies:
          - name: HK
            type: socks5
            server: 127.0.0.1
            port: 1080
        proxy-groups:
          - name: GLOBAL
            type: select
            proxies:
              - HK
              - DIRECT
        rules:
          - GEOSITE,cn,DIRECT
          - GEOIP,CN,DIRECT,no-resolve
          - IP-ASN,AS4134,GLOBAL,no-resolve
          - MATCH,GLOBAL
        """,
        controlledConfigYaml: "mode: rule",
        appConfigJson: "{}"
      )
    )
    expect(
      runtimeConfigWithExistingASN.components(separatedBy: "4134").count - 1 == 1,
      "runtime config should preserve a user-defined ASN rule without duplicating it"
    )
    expect(
      runtimeConfigWithExistingASN.contains("GEOSITE,cn,DIRECT")
        && runtimeConfigWithExistingASN.contains("GEOIP,CN,DIRECT,no-resolve")
        && runtimeConfigWithExistingASN.contains("IP-ASN,AS4134,GLOBAL,no-resolve")
        && !runtimeConfigWithExistingASN.contains("IP-ASN,4809,DIRECT,no-resolve"),
      "ASN support should remain opt-in through user profile rules instead of silently changing route decisions"
    )
    let proxyServerEndpointHosts = compatibilityService.extractProxyServerEndpointHosts(
      from: """
      proxies:
        - name: domain-host
          type: trojan
          server: okanc.iepl.cac.cab
          port: 30401
        - { name: ipv4-host, type: socks5, server: 203.0.113.7, port: 443 }
        - { name: ipv6-host, type: socks5, server: "[2001:db8::7]", port: 443 }
      """
    )
    expect(
      proxyServerEndpointHosts == ["okanc.iepl.cac.cab", "203.0.113.7", "2001:db8::7"],
      "packet tunnel route exclusion host extraction should keep domains and IP literals from proxy server endpoints"
    )
    let bootstrapDNSEndpointHosts = compatibilityService.extractBootstrapDNSEndpointHosts(
      from: """
      dns:
        enable: true
        nameserver:
          - 223.5.5.5
          - https://1.1.1.1/dns-query
        proxy-server-nameserver:
          - 119.29.29.29
          - tls://8.8.8.8:853
        default-nameserver:
          - "[2001:4860:4860::8888]"
        direct-nameserver:
          - 9.9.9.9
        fallback:
          - https://dns.example.invalid/dns-query
      """
    )
    expect(
      bootstrapDNSEndpointHosts == [
        "223.5.5.5",
        "1.1.1.1",
        "119.29.29.29",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "9.9.9.9"
      ],
      "packet tunnel DNS bootstrap route exclusion extraction should keep only configured IP literal DNS endpoints"
    )
    let selectedProxySummaryGroups = [
      ProxyGroupSnapshot(
        name: "🎯 全球直连",
        selected: "DIRECT",
        all: ["DIRECT", "🇭🇰香港01A"],
        type: "select"
      ),
      ProxyGroupSnapshot(
        name: "🚀 节点选择",
        selected: "🎁 自动选择",
        all: ["🎁 自动选择", "🇭🇰香港01A", "DIRECT"],
        type: "select"
      ),
      ProxyGroupSnapshot(
        name: "🎁 自动选择",
        selected: "🇭🇰香港01A",
        all: ["🇭🇰香港01A", "DIRECT"],
        type: "url-test"
      ),
      ProxyGroupSnapshot(
        name: "🐟 漏网之鱼",
        selected: "🚀 节点选择",
        all: ["🚀 节点选择", "DIRECT"],
        type: "select"
      )
    ]
    expect(
      selectedProxySummaryGroups[2].supportsManualSelection,
      "url-test proxy groups should be manually selectable when the user wants to pin a node"
    )
    let directOnlyStartupConnections = [
      ConnectionSnapshot(
        host: "imap.qq.com",
        chain: "DIRECT -> 🎯 全球直连",
        rule: "GeoIP"
      )
    ]
    expect(
      ProxySummaryResolver.activeProxySummary(
        proxyGroups: selectedProxySummaryGroups,
        connections: directOnlyStartupConnections
      ) == "🇭🇰香港01A",
      "home active proxy summary should prefer the selected proxy-group leaf over incidental DIRECT startup traffic"
    )
    expect(
      ProxySummaryResolver.activeProxySummary(
        proxyGroups: [],
        connections: [
          ConnectionSnapshot(
            host: "www.google.com",
            chain: "🇭🇰香港01A -> 🎁 自动选择 -> 🚀 节点选择 -> 🐟 漏网之鱼",
            rule: "Match"
          )
        ]
      ) == "🇭🇰香港01A",
      "connection-chain fallback should read mihomo chains as leaf-first when proxy groups are unavailable"
    )
    expect(
      ProxySummaryResolver.activeProxySummary(
        proxyGroups: [],
        connections: directOnlyStartupConnections
      ) == nil,
      "connection-chain fallback should ignore DIRECT-only chains instead of reporting DIRECT as the selected node"
    )
    let pendingRouteConnection = ConnectionSnapshot(
      host: "unknown",
      chain: "unknown",
      chainComponents: ["unknown"],
      rule: "",
      metadata: ConnectionSnapshot.Metadata(destinationIP: "142.250.72.196", destinationPort: 443)
    )
    let pendingRouteExplanation = RouteExplanationResolver.explain(pendingRouteConnection)
    expect(
      pendingRouteExplanation.host == "142.250.72.196:443",
      "route explanations should prefer concrete destination metadata over a controller 'unknown' placeholder"
    )
    expect(
      pendingRouteExplanation.finalNode == "Pending route",
      "route explanations should render incomplete controller chains as pending instead of an unknown node"
    )
    let legacyRouteExplanationJSON = """
    {
      "id": "legacy-route",
      "host": "unknown",
      "chainComponents": ["DIRECT"],
      "finalNode": "DIRECT",
      "outcome": "direct",
      "upload": 1,
      "download": 2
    }
    """.data(using: .utf8)!
    let decodedLegacyExplanation = try! JSONDecoder().decode(RouteExplanation.self, from: legacyRouteExplanationJSON)
    expect(
      decodedLegacyExplanation.host == "Pending route"
        && decodedLegacyExplanation.matchedRule == "MATCH"
        && decodedLegacyExplanation.dnsContext == .unknown,
      "route explanation cache decoding should tolerate stale records with missing newer fields"
    )

    let input = CompatibilityInput(
      profileYaml: profileYAML,
      controlledConfigYaml: "mode: rule",
      appConfigJson: appConfigJSON
    )
    let oldDate = Date(timeIntervalSince1970: 10)
    let newDate = Date(timeIntervalSince1970: 20)
    let existing = ProfileBundleRecord(
      id: "existing-remote-profile",
      name: "HK Stable",
      input: input,
      remoteSource: "http://192.168.1.3:25000/sub/stable",
      createdAt: oldDate,
      updatedAt: oldDate
    )

    let updated = ProfileBundleRecord.recordForRemoteImport(
      remoteSource: "http://192.168.1.3:25000/sub/stable",
      input: input,
      existingRecords: [existing],
      fallbackName: "Default Profile",
      now: newDate
    )
    expect(updated.id == existing.id, "remote import should update the existing record instead of creating a duplicate")
    expect(updated.name == existing.name, "remote import should preserve the existing record name")
    expect(updated.remoteSource == existing.remoteSource, "remote source should stay attached to the saved record")
    expect(updated.createdAt == existing.createdAt, "remote import should preserve the original createdAt timestamp")
    expect(updated.updatedAt == newDate, "remote import should bump the updatedAt timestamp")

    let refreshedInput = CompatibilityInput(
      profileYaml: """
      proxies:
        - name: SG-02
          type: socks5
          server: 127.0.0.2
          port: 2080
      proxy-groups:
        - type: select
          name: GLOBAL
          proxies:
            - SG-02
            - DIRECT
      rules:
        - MATCH,GLOBAL
      """,
      controlledConfigYaml: input.controlledConfigYaml,
      appConfigJson: input.appConfigJson
    )
    let refreshed = ProfileBundleRecord.recordForRemoteImport(
      remoteSource: " http://192.168.1.3:25000/sub/stable ",
      input: refreshedInput,
      existingRecords: [existing],
      fallbackName: nil,
      now: Date(timeIntervalSince1970: 30)
    )
    expect(refreshed.id == existing.id, "same remote import source should keep replacing the original record")
    expect(refreshed.input.profileYaml == refreshedInput.profileYaml, "same remote import source should replace the stored node list instead of merging stale nodes")
    expect(
      existing.matchesActiveWorkspace(
        input: existing.input,
        remoteSource: existing.remoteSource,
        activeProfileID: nil
      ),
      "deleting the active remote profile should be recognized so its nodes can be cleared synchronously"
    )
    expect(
      existing.matchesActiveWorkspace(
        input: refreshedInput,
        remoteSource: nil,
        activeProfileID: nil
      ) == false,
      "deleting a non-active profile should not clear an unrelated workspace"
    )

    let startupSnapshot = TunnelExtensionSnapshot(
      runtimeStatus: RuntimeStatus(
        state: .starting,
        vpnConnected: false,
        dataPlaneReady: false,
        startupPhase: "warmingProviders"
      ),
      startupPhase: "warmingProviders",
      controllerAddress: nil,
      running: false
    )
    expect(
      startupSnapshot.canAuthoritativelyReconcileProxyPreferences == false,
      "startup snapshots should not clear app-stored proxy preferences before the packet tunnel core reads them"
    )

    let runningSnapshot = TunnelExtensionSnapshot(
      runtimeStatus: RuntimeStatus(
        state: .running,
        vpnConnected: true,
        dataPlaneReady: true,
        startupPhase: "running"
      ),
      startupPhase: "running",
      controllerAddress: "127.0.0.1:35499",
      running: true
    )
    expect(
      runningSnapshot.canAuthoritativelyReconcileProxyPreferences,
      "running snapshots with a live controller can prune stale proxy preferences"
    )

    let fresh = ProfileBundleRecord.recordForRemoteImport(
      remoteSource: "http://192.168.1.3:25000/sub/other",
      input: input,
      existingRecords: [existing],
      fallbackName: nil,
      now: newDate
    )
    expect(fresh.id != existing.id, "a different remote source should create a new saved profile record")
    expect(fresh.remoteSource == "http://192.168.1.3:25000/sub/other", "new remote imports should persist their source URL")
    expect(fresh.name == "other", "new remote imports should derive a stable default name from the URL")

    print("PASS")
  }
}
