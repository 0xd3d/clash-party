import Foundation

public enum L10n {
  public static func string(_ key: String, _ defaultValue: String) -> String {
    Bundle.main.localizedString(forKey: key, value: defaultValue, table: nil)
  }

  public static func format(_ key: String, _ defaultValue: String, _ arguments: CVarArg...) -> String {
    let template = string(key, defaultValue)
    return String(format: template, locale: Locale.autoupdatingCurrent, arguments: arguments)
  }
}
