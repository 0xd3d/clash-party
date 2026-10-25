import Foundation

/// Core IPv6 disablement must not release physical-device IPv6 to the network.
/// Keep a capture-only interface and discard that family before core ingress.
struct PacketTunnelIPv6Policy: Equatable {
  let captureAddress: String
  let prefixLength: Int
  let dropsIPv6: Bool

  init(plan: PacketTunnelNetworkPlan) {
    captureAddress = plan.ipv6Address ?? "fdfe:dcba:9876::1"
    prefixLength = plan.ipv6PrefixLength ?? 126
    dropsIPv6 = plan.ipv6Address == nil
  }
}
