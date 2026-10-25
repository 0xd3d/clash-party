import Foundation

struct ProxySelectionRequest: Equatable {
  let groupName: String
  let proxy: String
}

enum ProxySelectionWaitReason {
  case controllerWarmup
  case providerWarmup
}

struct ProxySelectionRuntimeState {
  private(set) var inFlight = false
  private(set) var active: ProxySelectionRequest?
  private(set) var pending: [ProxySelectionRequest] = []
  private(set) var confirmed: [String: String] = [:]
  private(set) var preferred: [String: String] = [:]
  private(set) var waitReason: ProxySelectionWaitReason?

  var hasPending: Bool {
    !pending.isEmpty
  }

  var canBeginNextRequest: Bool {
    !inFlight && hasPending
  }

  var nextPendingRequest: ProxySelectionRequest? {
    canBeginNextRequest ? pending.first : nil
  }

  func contains(_ request: ProxySelectionRequest) -> Bool {
    active == request || pending.contains(request)
  }

  func hasNewerSelection(forGroup groupName: String) -> Bool {
    pending.contains { $0.groupName == groupName }
  }

  func confirmedSelection(for groupName: String) -> String? {
    confirmed[groupName]
  }

  func preferredSelection(for groupName: String) -> String? {
    preferred[groupName]
  }

  mutating func loadPreferredSelections(_ selections: [String: String]) {
    preferred = selections
  }

  mutating func storeConfirmedSelection(_ selection: String?, for groupName: String) {
    if let selection, !selection.isEmpty {
      confirmed[groupName] = selection
    } else {
      confirmed.removeValue(forKey: groupName)
    }
  }

  @discardableResult
  mutating func storePreferredSelection(_ selection: String?, for groupName: String) -> Bool {
    let normalizedSelection = selection?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let previousSelection = preferred[groupName]

    if normalizedSelection.isEmpty {
      guard previousSelection != nil else { return false }
      preferred.removeValue(forKey: groupName)
      return true
    }

    guard previousSelection != normalizedSelection else { return false }
    preferred[groupName] = normalizedSelection
    return true
  }

  mutating func materializePreferredSelections(within groups: [ProxyGroupSnapshot]) {
    preferred = ProxySelectionCoordinator.materializedPreferences(preferred, within: groups)
  }

  mutating func queue(_ request: ProxySelectionRequest) {
    pending.removeAll { $0.groupName == request.groupName }
    pending.append(request)
  }

  @discardableResult
  mutating func beginNextRequest() -> ProxySelectionRequest? {
    guard canBeginNextRequest else { return nil }
    waitReason = nil
    inFlight = true
    let request = pending.removeFirst()
    active = request
    return request
  }

  mutating func completeActiveRequest() {
    inFlight = false
    active = nil
    waitReason = nil
  }

  mutating func requeueIfNoNewerSelection(_ request: ProxySelectionRequest) {
    guard !hasNewerSelection(forGroup: request.groupName) else { return }
    pending.insert(request, at: 0)
  }

  @discardableResult
  mutating func waitFor(_ reason: ProxySelectionWaitReason) -> Bool {
    guard waitReason != reason else { return false }
    waitReason = reason
    return true
  }

  mutating func clearWaitReason() {
    waitReason = nil
  }

  mutating func clearPendingRuntimeState() {
    waitReason = nil
    inFlight = false
    active = nil
    pending.removeAll()
  }

  mutating func reset(resetPreferredSelections: Bool) {
    clearPendingRuntimeState()
    confirmed.removeAll()
    if resetPreferredSelections {
      preferred.removeAll()
    }
  }
}

struct ProxySelectionCoordinator {
  static func isSelection(_ selection: String?, validFor group: ProxyGroupSnapshot) -> Bool {
    let normalizedSelection = selection?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !normalizedSelection.isEmpty, group.supportsManualSelection else { return false }
    return group.selected == normalizedSelection || group.displayOptions.contains(normalizedSelection)
  }

  static func isKnownSelection(_ selection: String?, in group: ProxyGroupSnapshot) -> Bool {
    let normalizedSelection = selection?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard !normalizedSelection.isEmpty, group.supportsManualSelection else { return false }
    return group.selected == normalizedSelection
      || group.displayOptions.contains(normalizedSelection)
      || group.all.contains(normalizedSelection)
  }

  static func materializedPreferences(
    _ preferences: [String: String],
    within groups: [ProxyGroupSnapshot]
  ) -> [String: String] {
    guard !groups.isEmpty else { return preferences }

    let groupsByName = groups.reduce(into: [String: ProxyGroupSnapshot]()) { result, group in
      result[group.name] = group
    }
    return preferences.filter { groupName, selection in
      guard let group = groupsByName[groupName] else { return false }
      return isKnownSelection(selection, in: group)
    }
  }
}
