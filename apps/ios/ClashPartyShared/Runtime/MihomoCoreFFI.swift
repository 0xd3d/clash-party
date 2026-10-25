import Foundation

#if canImport(MihomoMobile)
import MihomoMobile
#endif

enum MihomoCoreFFIError: LocalizedError {
  case unavailable
  case coreError(String)

  var errorDescription: String? {
    switch self {
    case .unavailable:
      return L10n.string(
        "error.core.unavailable",
        "Embedded MihomoMobile core is not linked. Build the xcframework and add it to the Xcode project before enabling the real runtime."
      )
    case .coreError(let message):
      return message
    }
  }
}

enum MihomoCoreFFI {
  static var isAvailable: Bool {
    #if canImport(MihomoMobile)
    true
    #else
    false
    #endif
  }

  static func start(
    configPath: String,
    homeDirectory: String,
    controllerAddress: String,
    controllerSecret: String
  ) throws {
    #if canImport(MihomoMobile)
    let configCopy = strdup(configPath)
    let homeCopy = strdup(homeDirectory)
    let addressCopy = strdup(controllerAddress)
    let secretCopy = strdup(controllerSecret)
    defer {
      free(configCopy)
      free(homeCopy)
      free(addressCopy)
      free(secretCopy)
    }

    if let error = MihomoStart(configCopy, homeCopy, addressCopy, secretCopy) {
      throw MihomoCoreFFIError.coreError(takeString(error))
    }
    #else
    throw MihomoCoreFFIError.unavailable
    #endif
  }

  static func stop() throws {
    #if canImport(MihomoMobile)
    if let error = MihomoStop() {
      throw MihomoCoreFFIError.coreError(takeString(error))
    }
    #else
    throw MihomoCoreFFIError.unavailable
    #endif
  }

  static func reload() throws {
    #if canImport(MihomoMobile)
    if let error = MihomoReload() {
      throw MihomoCoreFFIError.coreError(takeString(error))
    }
    #else
    throw MihomoCoreFFIError.unavailable
    #endif
  }

  static func version() -> String {
    #if canImport(MihomoMobile)
    guard let value = MihomoVersion() else {
      return L10n.string("runtime.version.unknown", "Unknown")
    }
    return takeString(value)
    #else
    return L10n.string("runtime.version.core_unavailable", "Embedded core unavailable")
    #endif
  }

  static func controllerAddress() -> String? {
    #if canImport(MihomoMobile)
    guard let value = MihomoControllerAddress() else {
      return nil
    }
    return takeString(value)
    #else
    return nil
    #endif
  }

  static func startupPhase() -> String {
    #if canImport(MihomoMobile)
    guard let value = MihomoStartupPhase() else {
      return "idle"
    }
    return takeString(value)
    #else
    return "idle"
    #endif
  }

  static func startupMessage() -> String {
    #if canImport(MihomoMobile)
    guard let value = MihomoStartupMessage() else {
      return ""
    }
    return takeString(value)
    #else
    return ""
    #endif
  }

  static func lastStartupError() -> String? {
    #if canImport(MihomoMobile)
    guard let value = MihomoLastStartupError() else {
      return nil
    }
    let text = takeString(value)
    return text.isEmpty ? nil : text
    #else
    return nil
    #endif
  }

  static func isRunning() -> Bool {
    #if canImport(MihomoMobile)
    MihomoIsRunning() == 1
    #else
    false
    #endif
  }

  private static func takeString(_ pointer: UnsafeMutablePointer<CChar>) -> String {
    let value = String(cString: pointer)
    free(pointer)
    return value
  }
}
