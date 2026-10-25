import Foundation

struct ProxyDelayTestingState {
  private(set) var statuses: [String: ProxyDelayStatus] = [:]
  private(set) var groupsInFlight: Set<String> = []

  func isGroupInFlight(_ groupName: String) -> Bool {
    groupsInFlight.contains(groupName)
  }

  func status(for proxyName: String) -> ProxyDelayStatus? {
    let normalizedProxyName = Self.normalizedProxyName(proxyName)
    guard !normalizedProxyName.isEmpty else { return nil }
    return statuses[normalizedProxyName]
  }

  mutating func beginGroup(_ groupName: String, previewProxyNames: [String]) -> Bool {
    guard !groupsInFlight.contains(groupName) else { return false }
    groupsInFlight.insert(groupName)
    mark(.testing, for: previewProxyNames)
    return true
  }

  mutating func finishGroup(_ groupName: String) {
    groupsInFlight.remove(groupName)
  }

  mutating func applyGroupMeasurements(
    previewProxyNames: [String],
    measurements: [String: Int]
  ) -> [String] {
    let normalizedMeasurements = Self.normalizedMeasurements(measurements)
    let measuredProxyNames = Self.uniqueProxyNames(Array(normalizedMeasurements.keys))
    let proxyNamesToUpdate = Self.uniqueProxyNames(previewProxyNames + measuredProxyNames)

    for proxyName in proxyNamesToUpdate {
      if let delay = normalizedMeasurements[proxyName] {
        statuses[proxyName] = .available(delay)
      } else if previewProxyNames.contains(proxyName) {
        statuses[proxyName] = .unavailable
      }
    }

    return measuredProxyNames
  }

  mutating func failGroup(
    _ groupName: String,
    previewProxyNames: [String],
    status: ProxyDelayStatus
  ) {
    mark(status, for: previewProxyNames)
    finishGroup(groupName)
  }

  mutating func beginNode(_ proxyName: String) -> Bool {
    let normalizedProxyName = Self.normalizedProxyName(proxyName)
    guard !normalizedProxyName.isEmpty else { return false }
    guard statuses[normalizedProxyName] != .some(.testing) else { return false }
    statuses[normalizedProxyName] = .testing
    return true
  }

  mutating func applyNodeMeasurement(proxyName: String, delay: Int) {
    let normalizedProxyName = Self.normalizedProxyName(proxyName)
    guard !normalizedProxyName.isEmpty else { return }
    statuses[normalizedProxyName] = .available(delay)
  }

  mutating func failNode(proxyName: String, status: ProxyDelayStatus) {
    let normalizedProxyName = Self.normalizedProxyName(proxyName)
    guard !normalizedProxyName.isEmpty else { return }
    statuses[normalizedProxyName] = status
  }

  mutating func mark(_ status: ProxyDelayStatus, for proxyNames: [String]) {
    for proxyName in Self.uniqueProxyNames(proxyNames) {
      statuses[proxyName] = status
    }
  }

  mutating func reset() {
    statuses.removeAll()
    groupsInFlight.removeAll()
  }

  private static func normalizedMeasurements(_ measurements: [String: Int]) -> [String: Int] {
    measurements.reduce(into: [String: Int]()) { result, item in
      let proxyName = normalizedProxyName(item.key)
      guard !proxyName.isEmpty else { return }
      result[proxyName] = item.value
    }
  }

  private static func uniqueProxyNames(_ names: [String]) -> [String] {
    ProxyNameNormalizer.uniqueDisplayOptions(from: names)
  }

  private static func normalizedProxyName(_ proxyName: String) -> String {
    proxyName.trimmingCharacters(in: .whitespacesAndNewlines)
  }
}
