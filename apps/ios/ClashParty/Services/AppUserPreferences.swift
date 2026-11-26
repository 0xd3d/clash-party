import Foundation

/// Device-local UI preferences (not part of the imported Mihomo profile).
enum AppUserPreferences {
  private static let confirmBeforeDisconnectingVPNKey = "confirmBeforeDisconnectingVPN"

  private static var defaults: UserDefaults {
    if let suite = UserDefaults(suiteName: SharedStore.appGroupIdentifier) {
      return suite
    }
    return .standard
  }

  /// When enabled, in-app disconnect and Shortcuts "Stop VPN" require explicit confirmation in Clash Party.
  static var confirmBeforeDisconnectingVPN: Bool {
    get {
      guard defaults.object(forKey: confirmBeforeDisconnectingVPNKey) != nil else {
        return false
      }
      return defaults.bool(forKey: confirmBeforeDisconnectingVPNKey)
    }
    set {
      defaults.set(newValue, forKey: confirmBeforeDisconnectingVPNKey)
    }
  }
}