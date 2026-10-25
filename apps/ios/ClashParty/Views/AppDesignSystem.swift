import SwiftUI
import UIKit

enum AppPalette {
  static let accent = Color(uiColor: .systemBlue)
  static let accentFocus = Color(red: 0.00, green: 0.44, blue: 0.89)
  static let accentOnDark = Color(red: 0.16, green: 0.59, blue: 1.00)
  static let accentSoft = Color(uiColor: .systemBlue).opacity(0.10)
  static let ink = Color(uiColor: .label)
  static let inkMuted = Color(uiColor: .secondaryLabel)
  static let canvas = Color(uiColor: .secondarySystemGroupedBackground)
  static let parchment = Color(uiColor: .systemGroupedBackground)
  static let pearl = Color(uiColor: .tertiarySystemGroupedBackground)
  static let tileDark = Color(uiColor: .label)
  static let hairline = Color(uiColor: .separator).opacity(0.28)
  static let success = Color(uiColor: .systemGreen)
  static let warning = Color(uiColor: .systemOrange)
  static let danger = Color(uiColor: .systemRed)
}

struct AppLayoutMetrics: Equatable {
  let containerWidth: CGFloat
  var usesAccessibilityLayout = false

  var pageHorizontalPadding: CGFloat {
    if containerWidth < 360 {
      return 10
    }
    if containerWidth < 430 {
      return 14
    }
    if containerWidth < 720 {
      return 16
    }
    return 22
  }

  var pageVerticalPadding: CGFloat {
    containerWidth < 360 ? 10 : 12
  }

  var pageSpacing: CGFloat {
    containerWidth < 360 ? 14 : 18
  }

  var contentMaxWidth: CGFloat {
    containerWidth >= 720 ? 860 : .infinity
  }

  var contentWidth: CGFloat {
    let framedWidth = containerWidth >= 720 ? min(containerWidth, contentMaxWidth) : containerWidth
    return max(1, framedWidth - pageHorizontalPadding * 2)
  }

  var isNarrowPhone: Bool {
    contentWidth < 350
  }

  var isPhoneWidth: Bool {
    contentWidth < 560
  }

  var surfacePadding: CGFloat { isNarrowPhone ? 12 : 16 }

  var surfaceContentWidth: CGFloat {
    max(1, contentWidth - surfacePadding * 2)
  }

  func flexibleColumns(
    minimum: CGFloat,
    maximumCount: Int,
    spacing: CGFloat = 12,
    inSurface: Bool = false
  ) -> [GridItem] {
    let availableWidth = inSurface ? surfaceContentWidth : contentWidth
    let countByWidth = max(1, Int((availableWidth + spacing) / (minimum + spacing)))
    let count = usesAccessibilityLayout ? 1 : max(1, min(maximumCount, countByWidth))
    return Array(repeating: GridItem(.flexible(), spacing: spacing), count: count)
  }

  func adaptiveColumns(
    minimum: CGFloat,
    spacing: CGFloat = 12
  ) -> [GridItem] {
    if usesAccessibilityLayout { return [GridItem(.flexible(), spacing: spacing)] }
    return [GridItem(.adaptive(minimum: min(minimum, max(1, contentWidth))), spacing: spacing)]
  }
}

private struct AppLayoutMetricsKey: EnvironmentKey {
  static let defaultValue = AppLayoutMetrics(containerWidth: UIScreen.main.bounds.width)
}

extension EnvironmentValues {
  var appLayoutMetrics: AppLayoutMetrics {
    get { self[AppLayoutMetricsKey.self] }
    set { self[AppLayoutMetricsKey.self] = newValue }
  }
}

enum DisplayValue {
  static func bool(_ value: Bool) -> String {
    value ? L10n.string("common.enabled", "Enabled") : L10n.string("common.disabled", "Disabled")
  }

  static func yesNo(_ value: Bool) -> String {
    value ? L10n.string("common.yes", "Yes") : L10n.string("common.no", "No")
  }

  static func fallback(_ value: String) -> String {
    value.isEmpty ? L10n.string("common.na", "N/A") : value
  }

  static func noneIfEmpty(_ values: [String]) -> [String] {
    values.isEmpty ? [L10n.string("common.none", "None")] : values
  }

  static func bytes(_ count: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: count, countStyle: .binary)
  }

  static func connectionState(_ value: RuntimeConnectionState) -> String {
    switch value {
    case .idle:
      return L10n.string("runtime.state.idle", "Idle")
    case .starting:
      return L10n.string("runtime.state.starting", "Starting")
    case .running:
      return L10n.string("runtime.state.running", "Running")
    case .stopping:
      return L10n.string("runtime.state.stopping", "Stopping")
    case .stopped:
      return L10n.string("runtime.state.stopped", "Stopped")
    case .failed:
      return L10n.string("runtime.state.failed", "Failed")
    }
  }

  static func mode(_ value: String) -> String {
    switch value.lowercased() {
    case "rule":
      return L10n.string("runtime.mode.rule", "Rule")
    case "global":
      return L10n.string("runtime.mode.global", "Global")
    case "direct":
      return L10n.string("runtime.mode.direct", "Direct")
    default:
      return value.isEmpty ? L10n.string("common.unknown", "Unknown") : value
    }
  }
}

struct AppPageContainer<Content: View>: View {
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    GeometryReader { geometry in
      let metrics = AppLayoutMetrics(
        containerWidth: geometry.size.width,
        usesAccessibilityLayout: dynamicTypeSize.isAccessibilitySize
      )

      ScrollView {
        LazyVStack(alignment: .leading, spacing: metrics.pageSpacing) {
          content
        }
        .frame(width: metrics.contentWidth, alignment: .leading)
        .padding(.horizontal, metrics.pageHorizontalPadding)
        .padding(.top, metrics.pageVerticalPadding)
        .padding(.bottom, metrics.pageVerticalPadding + geometry.safeAreaInsets.bottom)
        .frame(maxWidth: metrics.contentMaxWidth)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .environment(\.appLayoutMetrics, metrics)
      }
      .safeAreaPadding(.bottom, 8)
      .scrollDismissesKeyboard(.interactively)
      .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardDidShowNotification)) { _ in
        Keyboard.revealFocusedField()
      }
      .background(AppSceneBackground())
      .toolbar {
        ToolbarItemGroup(placement: .keyboard) {
          Spacer()
          Button(L10n.string("action.done", "Done")) {
            Keyboard.dismiss()
          }
        }
      }
    }
  }
}

@MainActor
enum Keyboard {
  static func dismiss() {
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
  }

  static func revealFocusedField() {
    let windows = UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .filter { $0.activationState == .foregroundActive }
      .flatMap(\.windows)
    guard let window = windows.first(where: \.isKeyWindow),
          let focusedView = firstResponder(in: window) else { return }

    // Reveal the field in the outer page scroll view as well as any editor's
    // internal scroll view, after iOS has applied the keyboard safe area.
    var ancestor = focusedView.superview
    while let view = ancestor {
      if let scrollView = view as? UIScrollView {
        let target = focusedView.convert(focusedView.bounds, to: scrollView).insetBy(dx: 0, dy: -12)
        scrollView.scrollRectToVisible(target, animated: true)
      }
      ancestor = view.superview
    }
  }

  private static func firstResponder(in view: UIView) -> UIView? {
    if view.isFirstResponder { return view }
    for child in view.subviews {
      if let focused = firstResponder(in: child) { return focused }
    }
    return nil
  }
}

struct AppSceneBackground: View {
  var body: some View {
    AppPalette.parchment
    .ignoresSafeArea()
  }
}

struct AppSurface<Content: View>: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let title: String?
  let subtitle: String?
  let trailing: AnyView?
  let content: Content

  init(
    title: String? = nil,
    subtitle: String? = nil,
    trailing: AnyView? = nil,
    @ViewBuilder content: () -> Content
  ) {
    self.title = title
    self.subtitle = subtitle
    self.trailing = trailing
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      if title != nil || subtitle != nil || trailing != nil {
        Group {
          if layoutMetrics.usesAccessibilityLayout {
            VStack(alignment: .leading, spacing: 10) {
              headerText
              trailing
            }
          } else {
            HStack(alignment: .top, spacing: 12) {
              headerText
              Spacer(minLength: 0)
              trailing
            }
          }
        }
        .padding(.horizontal, 4)
      }
      content
        .padding(layoutMetrics.surfacePadding)
        .background(
          RoundedRectangle(cornerRadius: 20, style: .continuous)
            .fill(AppPalette.canvas)
        )
    }
  }

  private var headerText: some View {
    VStack(alignment: .leading, spacing: 4) {
      if let title {
        Text(title)
          .appFont(size: 15, weight: .semibold)
          .tracking(-0.18)
          .foregroundStyle(AppPalette.ink)
          .fixedSize(horizontal: false, vertical: true)
      }
      if let subtitle {
        Text(subtitle)
          .appFont(size: 13)
          .tracking(-0.12)
          .lineSpacing(2)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
  }
}

struct AppPageHeader: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let title: String
  let subtitle: String
  var icon: String? = nil
  var tint: Color = AppPalette.accent

  var body: some View {
    HStack(alignment: .top, spacing: 14) {
      if let icon {
        Image(systemName: icon)
          .appFont(size: 18, weight: .semibold)
          .foregroundStyle(tint)
          .frame(width: 42, height: 42)
          .background(tint.opacity(0.10), in: Circle())
      }

      VStack(alignment: .leading, spacing: 5) {
        Text(title)
          .appFont(size: layoutMetrics.isNarrowPhone ? 23 : 26, weight: .semibold, design: .default)
          .tracking(-0.34)
          .foregroundStyle(AppPalette.ink)
        Text(subtitle)
          .appFont(size: 15, weight: .regular, design: .default)
          .tracking(-0.18)
          .lineSpacing(2)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 4)
  }
}

struct AppGroupedList<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      content
    }
    .background(
      RoundedRectangle(cornerRadius: 20, style: .continuous)
        .fill(AppPalette.canvas)
    )
  }
}

struct AppListDivider: View {
  var leadingInset: CGFloat = 58

  var body: some View {
    Rectangle()
      .fill(AppPalette.hairline)
      .frame(height: 1 / UIScreen.main.scale)
      .padding(.leading, leadingInset)
  }
}

struct AppNavigationListRow: View {
  let title: String
  let subtitle: String
  let icon: String
  var tint: Color = AppPalette.accent

  var body: some View {
    HStack(alignment: .center, spacing: 12) {
      Image(systemName: icon)
        .appFont(size: 16, weight: .semibold)
        .foregroundStyle(tint)
        .frame(width: 34, height: 34)
        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))

      VStack(alignment: .leading, spacing: 3) {
        Text(title)
          .appFont(size: 16, weight: .semibold)
          .tracking(-0.24)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(1)
        Text(subtitle)
          .appFont(size: 13, weight: .regular)
          .tracking(-0.12)
          .lineSpacing(1)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }

      Spacer(minLength: 8)

      Image(systemName: "chevron.right")
        .appFont(size: 13, weight: .semibold)
        .foregroundStyle(.tertiary)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .contentShape(Rectangle())
  }
}

struct HeroCard<Content: View>: View {
  let eyebrow: String
  let title: String
  let subtitle: String
  let content: Content

  init(
    eyebrow: String,
    title: String,
    subtitle: String,
    @ViewBuilder content: () -> Content
  ) {
    self.eyebrow = eyebrow
    self.title = title
    self.subtitle = subtitle
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      VStack(alignment: .leading, spacing: 6) {
        Text(eyebrow.uppercased())
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
        Text(title)
          .appFont(size: 34, weight: .semibold, design: .default)
          .tracking(-0.37)
          .foregroundStyle(AppPalette.ink)
        Text(subtitle)
          .appFont(size: 17, weight: .regular)
          .tracking(-0.28)
          .lineSpacing(3)
          .foregroundStyle(.secondary)
      }
      content
    }
    .padding(24)
    .background(
      RoundedRectangle(cornerRadius: 28, style: .continuous)
        .fill(AppPalette.canvas)
    )
    .overlay(
      RoundedRectangle(cornerRadius: 28, style: .continuous)
        .stroke(AppPalette.hairline, lineWidth: 1)
    )
  }
}

struct PhoneStatusHero: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let eyebrow: String
  let title: String
  let subtitle: String
  let state: RuntimeConnectionState
  let primaryTitle: String
  let primaryIcon: String
  let primaryDisabled: Bool
  let primaryAction: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      HStack(alignment: .top, spacing: 14) {
        VStack(alignment: .leading, spacing: 7) {
          Text(eyebrow.uppercased())
            .appFont(size: 12, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(.secondary)
          Text(title)
            .appFont(size: layoutMetrics.isNarrowPhone ? 32 : 38, weight: .semibold, design: .default)
            .tracking(-0.28)
            .foregroundStyle(AppPalette.ink)
            .minimumScaleFactor(0.82)
            .lineLimit(2)
          Text(subtitle)
            .appFont(size: 17, weight: .regular)
            .tracking(-0.28)
            .lineSpacing(3)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        Spacer(minLength: 10)
        Image(systemName: stateIcon)
          .font(.title2.weight(.semibold))
          .foregroundStyle(stateTint)
          .frame(width: 44, height: 44)
          .background(stateTint.opacity(0.12), in: Circle())
      }

      Button(action: primaryAction) {
        Label(primaryTitle, systemImage: primaryIcon)
          .appFont(size: 17, weight: .regular)
          .tracking(-0.28)
          .frame(maxWidth: .infinity)
          .frame(minHeight: 46)
          .background(AppPalette.accent.opacity(primaryDisabled ? 0.42 : 1), in: Capsule())
      }
      .buttonStyle(.plain)
      .foregroundStyle(.white)
      .disabled(primaryDisabled)
    }
    .padding(20)
    .background(
      RoundedRectangle(cornerRadius: 24, style: .continuous)
        .fill(AppPalette.canvas)
    )
  }

  private var stateIcon: String {
    switch state {
    case .running:
      return "checkmark.shield.fill"
    case .starting:
      return "bolt.horizontal.circle.fill"
    case .stopping:
      return "pause.circle.fill"
    case .failed:
      return "exclamationmark.triangle.fill"
    default:
      return "power.circle.fill"
    }
  }

  private var heroFill: Color {
    AppPalette.canvas
  }

  private var stateTint: Color {
    switch state {
    case .running:
      return AppPalette.success
    case .failed:
      return AppPalette.danger
    case .starting, .stopping:
      return AppPalette.warning
    default:
      return AppPalette.accent
    }
  }
}

struct PhoneQuickAction: View {
  let title: String
  let subtitle: String
  let icon: String
  var tint: Color = AppPalette.accent
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      HStack(spacing: 12) {
        Image(systemName: icon)
          .appFont(size: 17, weight: .semibold)
          .foregroundStyle(tint)
          .frame(width: 36, height: 36)
          .background(tint.opacity(0.10), in: Circle())
        VStack(alignment: .leading, spacing: 3) {
          Text(title)
            .appFont(size: 16, weight: .semibold)
            .tracking(-0.24)
            .foregroundStyle(AppPalette.ink)
          Text(subtitle)
            .appFont(size: 13, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(.secondary)
            .lineLimit(2)
            .multilineTextAlignment(.leading)
        }
        Spacer(minLength: 0)
        Image(systemName: "chevron.right")
          .appFont(size: 13, weight: .semibold)
          .foregroundStyle(.tertiary)
      }
      .padding(14)
      .frame(maxWidth: .infinity, minHeight: 72, alignment: .leading)
      .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
    .buttonStyle(.plain)
  }
}

struct PhoneStatChip: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let title: String
  let value: String
  let icon: String
  var tint: Color = AppPalette.accent

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Image(systemName: icon)
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(tint)
      Text(value)
        .appFont(size: 17, weight: .semibold)
        .monospacedDigit()
        .tracking(-0.28)
        .foregroundStyle(AppPalette.ink)
        .lineLimit(layoutMetrics.usesAccessibilityLayout ? nil : 2)
        .fixedSize(horizontal: false, vertical: true)
      Text(title)
        .appFont(size: 12, weight: .regular)
        .tracking(-0.12)
        .foregroundStyle(.secondary)
        .lineLimit(1)
    }
    .padding(13)
    .frame(maxWidth: .infinity, minHeight: 92, alignment: .leading)
    .background(
      AppPalette.pearl,
      in: RoundedRectangle(cornerRadius: 16, style: .continuous)
    )
  }
}

struct StatusInfoChip: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let title: String
  let value: String
  let icon: String
  var tint: Color = AppPalette.accent

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack(spacing: 8) {
        Image(systemName: icon)
          .appFont(size: 13, weight: .semibold)
          .foregroundStyle(tint)
          .frame(width: 26, height: 26)
          .background(tint.opacity(0.10), in: Circle())
        Text(title)
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
          .lineLimit(layoutMetrics.usesAccessibilityLayout ? nil : 2)
      }
      Text(value)
        .appFont(size: 15, weight: .semibold)
        .tracking(-0.18)
        .foregroundStyle(AppPalette.ink)
        .lineLimit(layoutMetrics.usesAccessibilityLayout ? nil : 3)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    .padding(12)
    .frame(maxWidth: .infinity, minHeight: 88, alignment: .topLeading)
    .background(
      AppPalette.pearl,
      in: RoundedRectangle(cornerRadius: 16, style: .continuous)
    )
  }
}

struct NodeGroupCard: View {
  let title: String
  let selected: String
  let countLabel: String
  let icon: String

  var body: some View {
    HStack(spacing: 14) {
      Image(systemName: icon)
        .appFont(size: 16, weight: .semibold)
        .foregroundStyle(AppPalette.accent)
        .frame(width: 36, height: 36)
        .background(AppPalette.accentSoft, in: Circle())
      VStack(alignment: .leading, spacing: 4) {
        Text(title)
          .appFont(size: 16, weight: .semibold)
          .tracking(-0.24)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(2)
        Text(selected)
          .appFont(size: 13, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
          .lineLimit(2)
          .fixedSize(horizontal: false, vertical: true)
        Text(countLabel)
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.tertiary)
          .lineLimit(1)
      }
      Spacer(minLength: 8)
      Image(systemName: "chevron.right")
        .appFont(size: 13, weight: .semibold)
        .foregroundStyle(.tertiary)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }
}

struct InfoPill: View {
  let icon: String
  let title: String
  let value: String
  var tint: Color = AppPalette.accent

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: icon)
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(tint)
        .frame(width: 32, height: 32)
        .background(AppPalette.pearl, in: Circle())
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
        Text(value)
          .appFont(size: 15, weight: .semibold)
          .tracking(-0.18)
          .foregroundStyle(AppPalette.ink)
      }
      Spacer(minLength: 0)
    }
    .padding(12)
    .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
  }
}

struct MetricTile: View {
  let title: String
  let value: String
  let accent: Color

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Text(title)
        .appFont(size: 14, weight: .regular)
        .tracking(-0.18)
        .foregroundStyle(.secondary)
      Text(value)
        .appFont(size: 21, weight: .semibold, design: .default)
        .tracking(-0.18)
        .foregroundStyle(AppPalette.ink)
      RoundedRectangle(cornerRadius: 999)
        .fill(AppPalette.hairline)
        .frame(height: 6)
        .overlay(alignment: .leading) {
          RoundedRectangle(cornerRadius: 999)
            .fill(accent)
            .frame(width: 54, height: 6)
        }
    }
    .padding(16)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      RoundedRectangle(cornerRadius: 20, style: .continuous)
        .fill(AppPalette.pearl)
    )
  }
}

struct EmptyStateCard: View {
  let icon: String
  let title: String
  let message: String

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      Image(systemName: icon)
        .appFont(size: 21, weight: .semibold)
        .foregroundStyle(AppPalette.accent)
      Text(title)
        .appFont(size: 17, weight: .semibold)
        .tracking(-0.28)
        .foregroundStyle(AppPalette.ink)
      Text(message)
        .appFont(size: 14, weight: .regular)
        .tracking(-0.18)
        .lineSpacing(2)
        .foregroundStyle(.secondary)
    }
    .padding(20)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      RoundedRectangle(cornerRadius: 18, style: .continuous)
        .fill(AppPalette.pearl)
    )
  }
}

struct ValueRow: View {
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize
  let title: String
  let value: String

  var body: some View {
    Group {
      if dynamicTypeSize.isAccessibilitySize {
        stackedLayout
      } else {
        ViewThatFits(in: .horizontal) {
          HStack(alignment: .firstTextBaseline, spacing: 16) {
            titleText.fixedSize(horizontal: true, vertical: false)
            Spacer(minLength: 12)
            valueText
              .fixedSize(horizontal: true, vertical: false)
              .multilineTextAlignment(.trailing)
          }
          stackedLayout
        }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private var stackedLayout: some View {
    VStack(alignment: .leading, spacing: 4) {
      titleText
      valueText.multilineTextAlignment(.leading)
    }
  }

  private var titleText: some View {
    Text(title)
      .appFont(size: 15, weight: .regular)
      .tracking(-0.18)
      .foregroundStyle(.secondary)
      .lineLimit(2)
  }

  private var valueText: some View {
    Text(value)
      .appFont(size: 15, weight: .semibold)
      .tracking(-0.18)
      .foregroundStyle(AppPalette.ink)
      .fixedSize(horizontal: false, vertical: true)
      .textSelection(.enabled)
  }
}

struct WrappedValueGroup: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let title: String
  let values: [String]

  var body: some View {
    let displayValues = Array(DisplayValue.noneIfEmpty(values).enumerated())

    VStack(alignment: .leading, spacing: 10) {
      Text(title)
        .appFont(size: 17, weight: .semibold)
        .tracking(-0.28)
      LazyVGrid(columns: layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 96 : 120, spacing: 8), alignment: .leading, spacing: 8) {
        ForEach(displayValues, id: \.offset) { _, value in
          Text(value)
            .appFont(size: 14, weight: .regular)
            .tracking(-0.18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(AppPalette.pearl, in: Capsule())
        }
      }
    }
  }
}

struct EditorSurface: View {
  let title: String
  let prompt: String
  @Binding var text: String
  let minHeight: CGFloat

  var body: some View {
    AppSurface(title: title, subtitle: prompt) {
      TextEditor(text: $text)
        .font(.system(.footnote, design: .monospaced))
        .frame(minHeight: minHeight)
        .padding(14)
        .background(
          RoundedRectangle(cornerRadius: 18, style: .continuous)
            .fill(AppPalette.pearl)
        )
        .overlay(
          RoundedRectangle(cornerRadius: 18, style: .continuous)
            .stroke(AppPalette.hairline, lineWidth: 1)
        )
    }
  }
}

struct NavigationRowCard: View {
  let title: String
  let subtitle: String
  let icon: String

  var body: some View {
    HStack(spacing: 14) {
      Image(systemName: icon)
        .appFont(size: 16, weight: .semibold)
        .frame(width: 34, height: 34)
        .background(AppPalette.accentSoft, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        .foregroundStyle(AppPalette.accent)
      VStack(alignment: .leading, spacing: 4) {
        Text(title)
          .appFont(size: 16, weight: .semibold)
          .tracking(-0.24)
          .foregroundStyle(AppPalette.ink)
        Text(subtitle)
          .appFont(size: 13, weight: .regular)
          .tracking(-0.12)
          .lineSpacing(1)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }
      Spacer(minLength: 8)
      Image(systemName: "chevron.right")
        .appFont(size: 13, weight: .semibold)
        .foregroundStyle(.tertiary)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .contentShape(Rectangle())
  }
}

struct ActionTile: View {
  let title: String
  let icon: String
  var subtitle: String? = nil
  var tint: Color = AppPalette.accent
  var prominent = false
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      VStack(alignment: .leading, spacing: 12) {
        Image(systemName: icon)
          .appFont(size: 17, weight: .semibold)
          .foregroundStyle(prominent ? .white : tint)
          .frame(width: 38, height: 38)
          .background(
            prominent ? Color.white.opacity(0.16) : AppPalette.pearl,
            in: Circle()
          )

        Text(title)
          .appFont(size: 17, weight: .semibold)
          .tracking(-0.28)
          .foregroundStyle(prominent ? .white : .primary)
          .multilineTextAlignment(.leading)

        if let subtitle {
          Text(subtitle)
            .appFont(size: 14, weight: .regular)
            .tracking(-0.18)
            .foregroundStyle(prominent ? .white.opacity(0.78) : .secondary)
            .multilineTextAlignment(.leading)
            .lineLimit(2)
        }
      }
      .frame(maxWidth: .infinity, minHeight: 110, alignment: .topLeading)
      .padding(14)
      .background(backgroundShape)
    }
    .buttonStyle(.plain)
  }

  @ViewBuilder
  private var backgroundShape: some View {
    RoundedRectangle(cornerRadius: 20, style: .continuous)
      .fill(
        prominent
          ? AnyShapeStyle(tint)
          : AnyShapeStyle(AppPalette.pearl)
      )
      .overlay {
        RoundedRectangle(cornerRadius: 20, style: .continuous)
          .stroke(Color.clear, lineWidth: 1)
      }
  }
}

struct TagBadge: View {
  let title: String
  var tint: Color = AppPalette.accent

  var body: some View {
    Text(title)
      .appFont(size: 12, weight: .regular)
      .tracking(-0.12)
      .foregroundStyle(tint)
      .multilineTextAlignment(.leading)
      .fixedSize(horizontal: false, vertical: true)
      .padding(.horizontal, 12)
      .padding(.vertical, 7)
      .background(tint.opacity(0.10), in: Capsule())
  }
}

struct ApplePrimaryButtonStyle: ButtonStyle {
  @Environment(\.isEnabled) private var isEnabled

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .appFont(size: 17, weight: .regular)
      .tracking(-0.28)
      .foregroundStyle(.white)
      .padding(.horizontal, 22)
      .padding(.vertical, 11)
      .frame(minHeight: 44)
      .background(AppPalette.accent.opacity(isEnabled ? 1 : 0.42), in: Capsule())
      .scaleEffect(configuration.isPressed && isEnabled ? 0.95 : 1)
      .opacity(isEnabled ? 1 : 0.72)
      .animation(.easeOut(duration: 0.14), value: configuration.isPressed)
  }
}

struct AppleSecondaryButtonStyle: ButtonStyle {
  @Environment(\.isEnabled) private var isEnabled

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .appFont(size: 14, weight: .regular)
      .tracking(-0.18)
      .foregroundStyle(AppPalette.accent)
      .padding(.horizontal, 15)
      .padding(.vertical, 8)
      .frame(minHeight: 44)
      .background(AppPalette.accentSoft, in: Capsule())
      .opacity(isEnabled ? 1 : 0.55)
      .scaleEffect(configuration.isPressed && isEnabled ? 0.95 : 1)
      .animation(.easeOut(duration: 0.14), value: configuration.isPressed)
  }
}

struct AppleUtilityButtonStyle: ButtonStyle {
  @Environment(\.isEnabled) private var isEnabled

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .appFont(size: 14, weight: .regular)
      .tracking(-0.18)
      .foregroundStyle(AppPalette.ink)
      .padding(.horizontal, 15)
      .padding(.vertical, 8)
      .frame(minHeight: 44)
      .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
      .opacity(isEnabled ? 1 : 0.55)
      .scaleEffect(configuration.isPressed && isEnabled ? 0.95 : 1)
      .animation(.easeOut(duration: 0.14), value: configuration.isPressed)
  }
}

struct AppleTextFieldModifier: ViewModifier {
  func body(content: Content) -> some View {
    content
      .appFont(size: 17, weight: .regular)
      .tracking(-0.28)
      .padding(.horizontal, 16)
      .padding(.vertical, 12)
      .frame(minHeight: 44)
      .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
  }
}

extension View {
  func appFont(
    size: CGFloat,
    weight: Font.Weight = .regular,
    design: Font.Design = .default
  ) -> some View {
    modifier(AppScaledFont(size: size, weight: weight, design: design))
  }

  func appleTextField() -> some View {
    modifier(AppleTextFieldModifier())
  }
}

private struct AppScaledFont: ViewModifier {
  @ScaledMetric(relativeTo: .body) private var size: CGFloat = 17
  let weight: Font.Weight
  let design: Font.Design

  init(size: CGFloat, weight: Font.Weight, design: Font.Design) {
    _size = ScaledMetric(wrappedValue: size, relativeTo: .body)
    self.weight = weight
    self.design = design
  }

  func body(content: Content) -> some View {
    content.font(.system(size: size, weight: weight, design: design))
  }
}
