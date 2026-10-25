import Foundation
import NetworkExtension

enum MihomoPacketFlowBridge {
  private static func appendDiagnostic(_ message: String) {
    SharedStore.appendLogNonBlocking(level: "debug", message: message)
  }

  static func attach(_ flow: NEPacketTunnelFlow, dropIPv6: Bool = false) {
    appendDiagnostic("Swift bridge attach entered. Preparing to convert packet flow into an opaque pointer.")
    appendDiagnostic("Swift bridge is calling Objective-C attachPacketFlow(flow).")
    MihomoPacketFlowObjCBridge.attachPacketFlow(flow, dropIPv6: dropIPv6)
    appendDiagnostic("Swift bridge attach returned from the Objective-C bridge entrypoint.")
  }

  @discardableResult
  static func setDropIPv6(_ enabled: Bool, for flow: NEPacketTunnelFlow) -> Bool {
    MihomoPacketFlowObjCBridge.setDropIPv6(enabled, forPacketFlow: flow)
  }

  @discardableResult
  static func blockAllTraffic(for flow: NEPacketTunnelFlow) -> Bool {
    MihomoPacketFlowObjCBridge.blockAllTraffic(for: flow)
  }

  static func clear() {
    appendDiagnostic("Swift bridge clear called. Clearing packet flow attachment state.")
    MihomoPacketFlowObjCBridge.clearAttachment()
  }

  static var isAttached: Bool {
    MihomoPacketFlowObjCBridge.isAttached()
  }

  static var hasObservedRead: Bool {
    MihomoPacketFlowObjCBridge.hasObservedRead()
  }

  static var hasObservedSuccessfulWrite: Bool {
    MihomoPacketFlowObjCBridge.hasObservedSuccessfulWrite()
  }

  static var queueStatistics: [String: UInt64] {
    MihomoPacketFlowObjCBridge.queueStatistics().mapValues { $0.uint64Value }
  }

  static var hasObservedBidirectionalTraffic: Bool {
    hasObservedRead && hasObservedSuccessfulWrite
  }
}
