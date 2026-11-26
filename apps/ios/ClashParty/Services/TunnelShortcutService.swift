import Foundation
#if canImport(UIKit)
  import UIKit
#endif

enum TunnelShortcutError: LocalizedError {
  case noPublishedConfiguration
  case invalidConfiguration(String)
  case noProxyNodes
  case waitTimedOut
  case stopRequiresInAppConfirmation

  var errorDescription: String? {
    switch self {
    case .noPublishedConfiguration:
      return L10n.string(
        "shortcuts.error.no_config",
        "Open Clash Party once and publish a valid profile before using Shortcuts."
      )
    case let .invalidConfiguration(message):
      return message
    case .noProxyNodes:
      return L10n.string(
        "shortcuts.error.no_proxy",
        "Import a profile with at least one proxy node before starting the VPN tunnel."
      )
    case .waitTimedOut:
      return L10n.string(
        "shortcuts.error.wait_timeout",
        "The VPN tunnel did not become ready before the wait window expired."
      )
    case .stopRequiresInAppConfirmation:
      return L10n.string(
        "shortcuts.error.stop_requires_confirmation",
        "Disconnect confirmation is enabled. Open Clash Party and disconnect from the home screen."
      )
    }
  }
}

enum TunnelShortcutService {
  private static let compatibilityService = CompatibilityService()

  static func republishPublishedConfigurationIfValid() throws -> CompatibilityValidationReport {
    let input: CompatibilityInput
    do {
      input = try SharedStore.readCompatibilityInput()
    } catch {
      throw TunnelShortcutError.noPublishedConfiguration
    }
    let prepared = compatibilityService.prepareConfiguration(input)
    guard prepared.report.isValid else {
      throw TunnelShortcutError.invalidConfiguration(prepared.report.blockingErrors.joined(separator: "\n"))
    }
    guard !compatibilityService.extractProxyNodes(from: input.profileYaml).isEmpty else {
      throw TunnelShortcutError.noProxyNodes
    }
    return try compatibilityService.commitPreparedConfiguration(prepared)
  }

  static func startVPN() async throws {
    _ = try republishPublishedConfigurationIfValid()
    SharedStore.appendLog(level: "info", message: "Shortcuts requested a VPN connection attempt.")
    try await TunnelManager.shared.startTunnel()
  }

  static func stopVPN() async throws {
    if AppUserPreferences.confirmBeforeDisconnectingVPN {
      throw TunnelShortcutError.stopRequiresInAppConfirmation
    }
    SharedStore.appendLog(level: "info", message: "Shortcuts requested the VPN tunnel to stop.")
    try await TunnelManager.shared.stopTunnel()
  }

  /// Starts the tunnel when disconnected, then waits until international traffic matches the in-app Ready banner.
  /// If the tunnel is already internationally ready, returns immediately without reconnecting.
  @discardableResult
  static func connectAndWait(timeout: TimeInterval) async throws -> Bool {
    _ = try republishPublishedConfigurationIfValid()

    if try await isInternationallyReady() {
      return true
    }

    let observation = await TunnelManager.shared.currentRuntimeObservation()
    let status = observation.runtimeStatus
    let shouldStart =
      !status.vpnConnected && status.state != .starting && status.state != .running

    if shouldStart {
      try await startVPN()
    } else {
      SharedStore.appendLog(
        level: "info",
        message: "Shortcuts connect-and-wait skipped start because the tunnel is already connecting or connected; waiting for international readiness only."
      )
    }

    return try await waitForVPNReady(timeout: timeout)
  }

  /// Connects when needed, waits for international readiness, then opens `url` in the system browser.
  @discardableResult
  static func openURLWhenReady(_ url: URL, timeout: TimeInterval) async throws -> Bool {
    let ready = try await connectAndWait(timeout: timeout)
    guard ready else { return false }

    SharedStore.queueShortcutOpenURL(url)
    let opened = await openSystemURL(url)
    if opened {
      SharedStore.clearPendingShortcutOpenURL()
      SharedStore.appendLog(
        level: "info",
        message: "Shortcuts opened url=\(url.absoluteString) in the system browser."
      )
      return true
    }

    SharedStore.appendLog(
      level: "info",
      message: "Shortcuts queued deferred browser open for url=\(url.absoluteString); the app will open it when active."
    )
    return true
  }

  /// Opens a URL queued by a Shortcut when the app becomes active (UIApplication.open is unreliable in background intents).
  static func deliverPendingShortcutOpenIfNeeded() async {
#if canImport(UIKit)
    await MainActor.run {
      guard let url = SharedStore.consumePendingShortcutOpenURL() else { return }
      UIApplication.shared.open(url, options: [:]) { accepted in
        if !accepted {
          SharedStore.queueShortcutOpenURL(url)
        }
        SharedStore.appendLog(
          level: accepted ? "info" : "warning",
          message: "Shortcuts deferred open for url=\(url.absoluteString) accepted=\(accepted)."
        )
      }
    }
#endif
  }

  static func openSystemURL(_ url: URL) async -> Bool {
#if canImport(UIKit)
    await withCheckedContinuation { continuation in
      DispatchQueue.main.async {
        UIApplication.shared.open(url, options: [:]) { accepted in
          continuation.resume(returning: accepted)
        }
      }
    }
#else
    false
#endif
  }

  private static func isInternationallyReady() async throws -> Bool {
    let observation = await TunnelManager.shared.currentRuntimeObservation()
    let readiness = TrafficReadinessResolver.resolve(
      runtimeStatus: observation.runtimeStatus,
      extensionSnapshot: observation.extensionSnapshot
    )
    return TrafficReadinessResolver.isInternationalTrafficReady(readiness)
  }

  @discardableResult
  static func waitForVPNReady(timeout: TimeInterval) async throws -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      let observation = await TunnelManager.shared.currentRuntimeObservation()
      let status = observation.runtimeStatus
      if status.state == .failed {
        let detail = status.lastFailureReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        throw TunnelShortcutError.invalidConfiguration(
          detail.isEmpty ? L10n.string("shortcuts.error.vpn_failed", "The VPN tunnel failed during startup.") : detail
        )
      }
      let readiness = TrafficReadinessResolver.resolve(
        runtimeStatus: status,
        extensionSnapshot: observation.extensionSnapshot
      )
      if TrafficReadinessResolver.isInternationalTrafficReady(readiness) {
        return true
      }
      try await Task.sleep(for: .milliseconds(500))
    }
    return false
  }
}