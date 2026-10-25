import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
  guard condition() else {
    fputs("FAIL: \(message)\n", stderr)
    exit(1)
  }
}

@main
struct TunnelDiagnosticsCheck {
  static func main() throws {
    func diagnostic(_ status: RuntimeStatus, initial: Bool = false) -> TunnelStatusDiagnostic {
      TunnelStatusDiagnostic.make(
        statusText: "disconnected",
        isInactive: true,
        runtimeStatus: status,
        isInitialObservation: initial
      )
    }

    let manualStop = RuntimeStatus(state: .stopped, lastStopReason: TunnelStopReason.userInitiated.rawValue)
    expect(diagnostic(manualStop).level == "info", "a persisted user stop must not be logged as an error")
    let superseded = RuntimeStatus(state: .stopped, lastStopReason: TunnelStopReason.superseded.rawValue)
    expect(diagnostic(superseded).level == "info", "switching to another VPN must preserve the system's normal stop reason")

    let unknownStop = RuntimeStatus(state: .stopped)
    let unknownEntry = diagnostic(unknownStop)
    expect(unknownEntry.level == "warning", "a disconnect with missing evidence must remain visible as unknown")
    expect(unknownEntry.message.contains("Cause is unknown"), "missing reasons must not be inferred as a manual stop")
    expect(!unknownEntry.message.contains("Stopped by the user"), "unknown stop must not claim user intent")

    let yamlFailure = "yaml: mapping key \"geodata-mode\" already defined"
    var lateFailure = unknownStop
    lateFailure.lastFailureReason = yamlFailure
    lateFailure.lastFailurePhase = "loadingConfig"
    let failureEntry = diagnostic(lateFailure)
    expect(failureEntry.level == "error", "a persisted YAML startup failure must stay an error")
    expect(failureEntry.message.contains(yamlFailure), "startup failure detail must be retained")
    expect(failureEntry.message.contains("Last failure phase: loadingConfig"), "failure phase must survive idle state mapping")
    expect(unknownEntry != failureEntry, "a failure arriving after the same disconnected status must produce a new diagnostic")

    var failureThenUserStop = lateFailure
    failureThenUserStop.lastStopReason = TunnelStopReason.userInitiated.rawValue
    expect(diagnostic(failureThenUserStop).level == "error", "a subsequent user stop must not hide an actual startup failure")
    expect(diagnostic(failureThenUserStop).message.contains(yamlFailure), "coexisting provider stop and failure details must both be logged")
    expect(diagnostic(RuntimeStatus(state: .failed)).level == "error", "failed runtime without detail must not be downgraded")

    let starting = RuntimeStatus(state: .starting)
    expect(diagnostic(starting).level == "info", "startup grace must not become a disconnect error")
    var failedStart = starting
    failedStart.lastFailureReason = yamlFailure
    expect(diagnostic(failedStart).level == "error", "startup grace must not hide a recorded failure")

    for state in [RuntimeConnectionState.idle, .stopped] {
      let offline = RuntimeStatus(state: state)
      let entry = diagnostic(offline, initial: true)
      expect(entry.level == "info", "initial inactive observation is not a newly observed disconnect")
      var newer = offline
      newer.updatedAt = .now.addingTimeInterval(60)
      expect(entry == diagnostic(newer, initial: true), "timestamp-only polling must not create duplicate diagnostics")
    }

    var whitespace = manualStop
    whitespace.lastFailureReason = " \n "
    whitespace.lastStopReason = " \n" + TunnelStopReason.userInitiated.rawValue + "  "
    expect(diagnostic(whitespace).level == "info", "blank failure strings must not turn normal stops into errors")
    let futureReason = RuntimeStatus(state: .stopped, lastStopReason: "Unknown future OS reason (99).")
    expect(diagnostic(futureReason).level == "warning", "unrecognized OS reasons must remain unknown")

    for reason in [TunnelStopReason.providerFailed, .internalError, .configurationFailed, .connectionFailed] {
      expect(diagnostic(RuntimeStatus(state: .stopped, lastStopReason: reason.rawValue)).level == "error", "explicit system failure must remain an error: \(reason)")
    }
    for reason in [TunnelStopReason.none, .noNetworkAvailable, .unrecoverableNetworkChange] {
      expect(diagnostic(RuntimeStatus(state: .stopped, lastStopReason: reason.rawValue)).level == "warning", "network loss or missing OS cause must remain visible: \(reason)")
    }

    var stopping = failureThenUserStop
    stopping.state = .stopping
    stopping.mode = "global"
    stopping.activeProfileId = "profile-kept"
    stopping.fakeDnsEnabled = true
    stopping.backend = "embedded-mihomo"
    stopping.dataPlaneReady = true
    stopping.vpnConnected = true
    let cleanedUp = stopping.stoppedPreservingDiagnostics(message: "Stopped.")
    expect(cleanedUp.state == .stopped && !cleanedUp.vpnConnected && !cleanedUp.dataPlaneReady, "cleanup must clear live state")
    expect(cleanedUp.lastFailureReason == yamlFailure && cleanedUp.lastFailurePhase == "loadingConfig", "core cleanup must preserve failure evidence")
    expect(cleanedUp.lastStopReason == stopping.lastStopReason, "core cleanup must preserve the provider stop reason written before cleanup")
    expect(cleanedUp.mode == "global" && cleanedUp.activeProfileId == "profile-kept" && cleanedUp.fakeDnsEnabled, "cleanup must preserve profile and DNS context")

    let legacyJSON = Data("{\"state\":\"stopped\",\"mode\":\"rule\"}".utf8)
    let legacy = try JSONDecoder().decode(RuntimeStatus.self, from: legacyJSON)
    expect(legacy.lastStopReason == nil && diagnostic(legacy).level == "warning", "older snapshots without reasons must remain readable and unconfirmed")
    let roundTrip = try JSONDecoder().decode(RuntimeStatus.self, from: JSONEncoder().encode(cleanedUp))
    expect(roundTrip == cleanedUp, "persisted diagnostics must round-trip without schema changes")

    print("PASS: manual/superseded/unknown stops, late startup errors, startup grace, initial offline observations, cleanup preservation and legacy JSON.")
  }
}
