import SwiftUI

enum PrimaryTab: Int, CaseIterable, Hashable {
  case home
  case nodes
  case more

  var title: String {
    switch self {
    case .home:
      L10n.string("nav.home", "Home")
    case .nodes:
      L10n.string("nav.nodes", "Nodes")
    case .more:
      L10n.string("nav.more", "More")
    }
  }

  var icon: String {
    switch self {
    case .home:
      "gauge.with.needle"
    case .nodes:
      "point.3.connected.trianglepath.dotted"
    case .more:
      "square.grid.2x2"
    }
  }
}

enum RuntimeDestination: String, CaseIterable, Hashable, Identifiable {
  case rules
  case dns
  case connections
  case logs

  var id: String { rawValue }

  var title: String {
    switch self {
    case .rules:
      L10n.string("page.rules", "Rules")
    case .dns:
      L10n.string("page.dns", "DNS")
    case .connections:
      L10n.string("page.connections", "Connections")
    case .logs:
      L10n.string("page.logs", "Logs")
    }
  }

  var icon: String {
    switch self {
    case .rules:
      "list.number"
    case .dns:
      "network"
    case .connections:
      "arrow.left.arrow.right.circle"
    case .logs:
      "list.bullet.rectangle.portrait"
    }
  }

  var subtitle: String {
    switch self {
    case .rules:
      L10n.string("runtime.rules.subtitle", "Inspect rule previews and policy targets.")
    case .dns:
      L10n.string("runtime.dns.subtitle", "Review Fake DNS, nameserver policy, and hijack inputs.")
    case .connections:
      L10n.string("runtime.connections.subtitle", "Follow active chains, traffic, and applied rules.")
    case .logs:
      L10n.string("runtime.logs.subtitle", "Monitor live runtime events and warnings.")
    }
  }
}

enum MoreDestination: String, CaseIterable, Hashable, Identifiable {
  case profiles
  case ruleInsight
  case rules
  case dns
  case connections
  case logs
  case resources
  case core
  case override
  case settings

  var id: String { rawValue }

  var title: String {
    switch self {
    case .profiles:
      L10n.string("nav.profiles", "Profiles")
    case .ruleInsight:
      L10n.string("page.rule_insight", "Rule Insight")
    case .rules:
      L10n.string("page.rules", "Rules")
    case .dns:
      L10n.string("page.dns", "DNS")
    case .connections:
      L10n.string("page.connections", "Connections")
    case .logs:
      L10n.string("page.logs", "Logs")
    case .resources:
      L10n.string("page.resources", "Resources")
    case .core:
      L10n.string("page.core", "Core")
    case .override:
      L10n.string("page.override", "Override")
    case .settings:
      L10n.string("page.settings", "Settings")
    }
  }

  var icon: String {
    switch self {
    case .profiles:
      "rectangle.stack.fill"
    case .ruleInsight:
      "point.topleft.down.curvedto.point.bottomright.up"
    case .rules:
      "list.number"
    case .dns:
      "network"
    case .connections:
      "arrow.left.arrow.right.circle"
    case .logs:
      "list.bullet.rectangle.portrait"
    case .resources:
      "shippingbox"
    case .core:
      "bolt.shield"
    case .override:
      "wand.and.stars"
    case .settings:
      "gearshape"
    }
  }

  var subtitle: String {
    switch self {
    case .profiles:
      L10n.string("more.profiles.subtitle", "Import subscriptions, keep templates, and manage saved bundles.")
    case .ruleInsight:
      L10n.string("more.rule_insight.subtitle", "Explain why active traffic selected its rule, chain, and final node.")
    case .rules:
      L10n.string("runtime.rules.subtitle", "Inspect rule previews and policy targets.")
    case .dns:
      L10n.string("runtime.dns.subtitle", "Review Fake DNS, nameserver policy, and hijack inputs.")
    case .connections:
      L10n.string("runtime.connections.subtitle", "Follow active chains, traffic, and applied rules.")
    case .logs:
      L10n.string("runtime.logs.subtitle", "Monitor live runtime events and warnings.")
    case .resources:
      L10n.string("more.resources.subtitle", "Remote providers, URLs, and sync metadata.")
    case .core:
      L10n.string("more.core.subtitle", "Mihomo and TUN runtime summaries.")
    case .override:
      L10n.string("more.override.subtitle", "Routing, DNS and resource overrides.")
    case .settings:
      L10n.string("more.settings.subtitle", "App preferences, configuration import and exports.")
    }
  }
}

enum AppDestination: Hashable, Identifiable {
  case home
  case nodes
  case more(MoreDestination)

  var id: String {
    switch self {
    case .home:
      "home"
    case .nodes:
      "nodes"
    case .more(let destination):
      "more.\(destination.rawValue)"
    }
  }
}

struct AppShellView: View {
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize
  let viewModel: ConsoleViewModel
  @ObservedObject var shellPresentation: ShellPresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void

  @State private var selectedTab: PrimaryTab = .home
  @State private var morePath: [AppDestination] = []
  @State private var splitSelection: AppDestination? = .home

  private var usesSplitView: Bool {
    UIDevice.current.userInterfaceIdiom == .pad
  }

  var body: some View {
    GeometryReader { geometry in
      Group {
        if usesSplitView {
          splitViewShell
            .safeAreaInset(edge: .bottom, spacing: 0) { activityBanner }
        } else {
          phoneShell
        }
      }
      .environment(\.appLayoutMetrics, AppLayoutMetrics(
        containerWidth: geometry.size.width,
        usesAccessibilityLayout: dynamicTypeSize.isAccessibilitySize
      ))
      .tint(AppPalette.accent)
    }
  }

  @ViewBuilder
  private var activityBanner: some View {
    if shellPresentation.state.isShowingActivity,
       let activityMessage = shellPresentation.state.activityMessage {
      BusyStatusBanner(message: activityMessage)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .allowsHitTesting(false)
    }
  }

  private var phoneShell: some View {
    TabView(selection: $selectedTab) {
      NavigationStack {
        OverviewPage(
          viewModel: viewModel,
          presentation: viewModel.overviewPresentation,
          onImportRequested: onImportRequested,
          onOpenProfiles: {
            selectedTab = .more
            morePath = [.more(.profiles)]
          },
          onOpenProxies: { selectedTab = .nodes },
          onOpenRuntime: { destination in
            selectedTab = .more
            morePath = [.more(mapRuntimeDestination(destination))]
          },
          onOpenMore: { destination in
            selectedTab = .more
            morePath = [.more(destination)]
          }
        )
      }
      .safeAreaInset(edge: .bottom, spacing: 0) { activityBanner }
      .tabItem { Label(PrimaryTab.home.title, systemImage: PrimaryTab.home.icon) }
      .tag(PrimaryTab.home)

      NavigationStack {
        ProxiesPage(viewModel: viewModel)
      }
      .safeAreaInset(edge: .bottom, spacing: 0) { activityBanner }
      .tabItem { Label(PrimaryTab.nodes.title, systemImage: PrimaryTab.nodes.icon) }
      .tag(PrimaryTab.nodes)

      NavigationStack(path: $morePath) {
        MoreHubPage()
          .navigationDestination(for: AppDestination.self) { destination in
            detailPage(for: destination)
          }
      }
      .safeAreaInset(edge: .bottom, spacing: 0) { activityBanner }
      .tabItem { Label(PrimaryTab.more.title, systemImage: PrimaryTab.more.icon) }
      .tag(PrimaryTab.more)
    }
  }

  private var splitViewShell: some View {
    NavigationSplitView {
      List(selection: $splitSelection) {
        Section(L10n.string("more.section.primary", "Primary")) {
          NavigationLink(value: AppDestination.home) {
            Label(PrimaryTab.home.title, systemImage: PrimaryTab.home.icon)
          }
          NavigationLink(value: AppDestination.nodes) {
            Label(PrimaryTab.nodes.title, systemImage: PrimaryTab.nodes.icon)
          }
          ForEach(primaryMoreDestinations) { destination in
            NavigationLink(value: AppDestination.more(destination)) {
              Label(destination.title, systemImage: destination.icon)
            }
          }
        }

        Section(L10n.string("more.section.diagnostics", "Diagnostics")) {
          ForEach(diagnosticMoreDestinations) { destination in
            NavigationLink(value: AppDestination.more(destination)) {
              Label(destination.title, systemImage: destination.icon)
            }
          }
        }

        Section(L10n.string("more.section.advanced", "Advanced")) {
          ForEach(advancedMoreDestinations) { destination in
            NavigationLink(value: AppDestination.more(destination)) {
              Label(destination.title, systemImage: destination.icon)
            }
          }
        }
      }
      .navigationTitle(L10n.string("app.title", "Clash Party iOS"))
      .listStyle(.sidebar)
    } detail: {
      switch splitSelection ?? .home {
      case .home:
        NavigationStack {
          OverviewPage(
            viewModel: viewModel,
            presentation: viewModel.overviewPresentation,
            onImportRequested: onImportRequested,
            onOpenProfiles: { splitSelection = .more(.profiles) },
            onOpenProxies: { splitSelection = .nodes },
            onOpenRuntime: { splitSelection = .more(mapRuntimeDestination($0)) },
            onOpenMore: { splitSelection = .more($0) }
          )
        }
      case .nodes:
        NavigationStack { ProxiesPage(viewModel: viewModel) }
      case .more(let destination):
        NavigationStack { morePage(for: destination) }
      }
    }
  }

  @ViewBuilder
  private func morePage(for destination: MoreDestination) -> some View {
    switch destination {
    case .profiles:
      ProfilesPage(viewModel: viewModel, onImportRequested: onImportRequested)
    case .ruleInsight:
      RuleInsightPage(viewModel: viewModel)
    case .rules:
      RulesPage(viewModel: viewModel, onImportRequested: onImportRequested)
    case .dns:
      DnsPage(viewModel: viewModel)
    case .connections:
      ConnectionsPage(viewModel: viewModel)
    case .logs:
      LogsPage(viewModel: viewModel)
    case .resources:
      ResourcesPage(viewModel: viewModel)
    case .core:
      CorePage(viewModel: viewModel)
    case .override:
      OverridePage(viewModel: viewModel, onImportRequested: onImportRequested)
    case .settings:
      SettingsPage(viewModel: viewModel, onImportRequested: onImportRequested)
    }
  }

  @ViewBuilder
  private func detailPage(for destination: AppDestination) -> some View {
    switch destination {
    case .home:
      OverviewPage(
        viewModel: viewModel,
        presentation: viewModel.overviewPresentation,
        onImportRequested: onImportRequested,
        onOpenProfiles: {
          morePath = [.more(.profiles)]
        },
        onOpenProxies: { selectedTab = .nodes },
        onOpenRuntime: { runtime in
          morePath = [.more(mapRuntimeDestination(runtime))]
        },
        onOpenMore: { more in
          morePath = [.more(more)]
        }
      )
    case .nodes:
      ProxiesPage(viewModel: viewModel)
    case .more(let destination):
      morePage(for: destination)
    }
  }

  private func mapRuntimeDestination(_ destination: RuntimeDestination) -> MoreDestination {
    switch destination {
    case .rules:
      .rules
    case .dns:
      .dns
    case .connections:
      .connections
    case .logs:
      .logs
    }
  }

  private var primaryMoreDestinations: [MoreDestination] {
    [.profiles, .ruleInsight, .settings]
  }

  private var diagnosticMoreDestinations: [MoreDestination] {
    [.dns, .rules, .connections, .logs]
  }

  private var advancedMoreDestinations: [MoreDestination] {
    [.resources, .core, .override]
  }
}

private struct BusyStatusBanner: View {
  let message: String

  var body: some View {
    HStack(spacing: 12) {
      ProgressView()
        .tint(AppPalette.accent)
      Text(message)
        .appFont(size: 14, weight: .regular)
        .tracking(-0.18)
        .foregroundStyle(AppPalette.ink)
        .multilineTextAlignment(.leading)
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 16)
    .padding(.vertical, 14)
    .background(
      RoundedRectangle(cornerRadius: 18, style: .continuous)
        .fill(AppPalette.canvas)
    )
    .overlay(
      RoundedRectangle(cornerRadius: 18, style: .continuous)
        .stroke(AppPalette.hairline, lineWidth: 1)
    )
  }
}
