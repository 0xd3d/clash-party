import SwiftUI

struct OverviewPage: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let viewModel: ConsoleViewModel
  @ObservedObject var presentation: OverviewPresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void
  var onOpenProfiles: (() -> Void)? = nil
  var onOpenProxies: (() -> Void)? = nil
  var onOpenRuntime: ((RuntimeDestination) -> Void)? = nil
  var onOpenMore: ((MoreDestination) -> Void)? = nil

  var body: some View {
    AppPageContainer {
      PhoneStatusHero(
        eyebrow: L10n.string("overview.hero.eyebrow", "Clash Party iOS"),
        title: DisplayValue.connectionState(presentation.state.runtimeState),
        subtitle: heroStatusSubtitle,
        state: presentation.state.runtimeState,
        primaryTitle: primaryHeroActionTitle,
        primaryIcon: primaryHeroActionIcon,
        primaryDisabled: presentation.state.tunnelControlsDisabled
      ) {
        if presentation.state.runtimeState == .running {
          viewModel.stopTunnel()
        } else if !presentation.state.hasProxyNodes {
          onOpenProfiles?()
        } else {
          viewModel.startTunnel()
        }
      }

      if !presentation.state.hasProxyNodes {
        AppSurface(
          title: L10n.string("overview.onboarding.title", "Start by importing a subscription"),
          subtitle: L10n.string(
            "overview.onboarding.subtitle",
            "Paste a URL or import a local profile bundle. The imported profile becomes the current workspace automatically."
          )
        ) {
          VStack(alignment: .leading, spacing: 12) {
            Button(L10n.string("action.import_config", "Import Config")) {
              onOpenProfiles?()
            }
            .buttonStyle(ApplePrimaryButtonStyle())

            if let lastRemoteImportSource = presentation.state.lastRemoteImportSource {
              ValueRow(
                title: L10n.string("profiles.current.last_remote", "Last Remote Import"),
                value: lastRemoteImportSource
              )
            }
          }
        }
      }

      AppSurface(
        title: L10n.string("overview.plan.title", "Connection Plan"),
        subtitle: L10n.string(
          "overview.plan.subtitle",
          "Check the selected node, profile, and startup phase before you connect."
        )
      ) {
        VStack(alignment: .leading, spacing: 14) {
          LazyVGrid(columns: statusColumns, spacing: 10) {
            StatusInfoChip(
              title: L10n.string("overview.connect.node", "Selected Node"),
              value: activeProxySummary,
              icon: "location.fill",
              tint: AppPalette.success
            )
            StatusInfoChip(
              title: L10n.string("runtime.summary.mode", "Mode"),
              value: DisplayValue.mode(presentation.state.runtimeMode),
              icon: "switch.2",
              tint: AppPalette.accent
            )
            StatusInfoChip(
              title: L10n.string("overview.connect.profile", "Current Profile"),
              value: currentProfileSummary,
              icon: "rectangle.stack.fill",
              tint: AppPalette.warning
            )
            StatusInfoChip(
              title: L10n.string("overview.connect.phase", "Startup Phase"),
              value: runtimePhaseSummary,
              icon: "waveform.path.ecg",
              tint: runtimePhaseTint
            )
          }

          if !planStartupMessage.isEmpty {
            Text(planStartupMessage)
              .font(.footnote)
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
          }

          LazyVGrid(columns: primaryActionColumns, spacing: 12) {
            PhoneQuickAction(
              title: L10n.string("action.import_config", "Import Subscription"),
              subtitle: L10n.string("overview.controls.import_subtitle", "Paste a URL, update the active profile, or manage saved bundles."),
              icon: "square.and.arrow.down",
              tint: AppPalette.accent
            ) {
              onOpenProfiles?()
            }

            PhoneQuickAction(
              title: L10n.string("nav.nodes", "Switch Node"),
              subtitle: L10n.string("overview.shortcuts.proxies", "Open proxy groups and pin a better route."),
              icon: "point.3.connected.trianglepath.dotted",
              tint: AppPalette.success
            ) {
              onOpenProxies?()
            }
          }
        }
      }

      if let lastError = presentation.state.lastError {
        AppSurface(
          title: L10n.string("overview.error.title", "Last Error"),
          subtitle: L10n.string("overview.error.subtitle", "Most recent blocking error surfaced by the app or runtime.")
        ) {
          Text(lastError)
            .font(.footnote)
            .foregroundStyle(AppPalette.danger)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
      }

      if shouldShowStartupDiagnostics {
        AppSurface(
          title: L10n.string("overview.diagnostics.title", "Startup Diagnostics"),
          subtitle: L10n.string(
            "overview.diagnostics.subtitle",
            "Latest Packet Tunnel phase, failure details, and stop reason."
          )
        ) {
          VStack(alignment: .leading, spacing: 12) {
            ValueRow(
              title: L10n.string("overview.connect.phase", "Startup Phase"),
              value: runtimePhaseSummary
            )
            if let lastFailurePhase, !lastFailurePhase.isEmpty {
              ValueRow(
                title: L10n.string("runtime.summary.failure_phase", "Failure Phase"),
                value: lastFailurePhase
              )
            }
            if let lastStopReason, !lastStopReason.isEmpty {
              ValueRow(
                title: L10n.string("runtime.summary.stop_reason", "Provider Stop Reason"),
                value: lastStopReason
              )
            }
            if !diagnosticStartupMessage.isEmpty {
              Text(diagnosticStartupMessage)
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            if let lastFailureReason, !lastFailureReason.isEmpty {
              Text(lastFailureReason)
                .font(.footnote)
                .foregroundStyle(AppPalette.danger)
            }
          }
        }
      }

      AppSurface(
        title: L10n.string("overview.metrics.title", "Tunnel Health"),
        subtitle: L10n.string("overview.metrics.subtitle", "Live VPN, data-plane, DNS, and traffic signals.")
      ) {
        LazyVGrid(columns: metricColumns, spacing: 12) {
          PhoneStatChip(
            title: L10n.string("runtime.summary.vpn", "VPN"),
            value: vpnSummary,
            icon: "lock.shield",
            tint: vpnConnected ? AppPalette.success : AppPalette.warning
          )
          PhoneStatChip(
            title: L10n.string("runtime.summary.data_plane", "Data Plane"),
            value: dataPlaneSummary,
            icon: "arrow.left.arrow.right.circle",
            tint: dataPlaneReady ? AppPalette.success : AppPalette.warning
          )
          PhoneStatChip(
            title: L10n.string("runtime.summary.fake_dns", "Fake DNS"),
            value: DisplayValue.bool(presentation.state.fakeDnsEnabled),
            icon: "network",
            tint: AppPalette.accent
          )
          PhoneStatChip(
            title: L10n.string("overview.metrics.traffic", "Traffic"),
            value: trafficSummary,
            icon: "arrow.up.arrow.down.circle",
            tint: AppPalette.success
          )
        }
      }

      AppSurface(
        title: L10n.string("overview.shortcuts.title", "Runtime Tools"),
        subtitle: L10n.string(
          "overview.shortcuts.subtitle",
          "Open deeper diagnostics when DNS, routing, or profile state needs attention."
        )
      ) {
        AppGroupedList {
          let shortcuts = overviewShortcuts
          let lastShortcutID = shortcuts.last?.id
          ForEach(shortcuts) { shortcut in
            Button(action: shortcut.action) {
              AppNavigationListRow(title: shortcut.title, subtitle: shortcut.subtitle, icon: shortcut.icon)
            }
            .buttonStyle(.plain)
            if shortcut.id != lastShortcutID {
              AppListDivider(leadingInset: 60)
            }
          }
        }
      }
    }
    .navigationTitle(L10n.string("nav.home", "Home"))
    .navigationBarTitleDisplayMode(.inline)
  }

  private var metricColumns: [GridItem] {
    layoutMetrics.flexibleColumns(minimum: 168, maximumCount: 2, spacing: 12, inSurface: true)
  }

  private var statusColumns: [GridItem] {
    layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 132 : 154, spacing: 10)
  }

  private var primaryActionColumns: [GridItem] {
    layoutMetrics.flexibleColumns(minimum: 260, maximumCount: 2, spacing: 12, inSurface: true)
  }

  private struct OverviewShortcut: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let icon: String
    let action: () -> Void
  }

  private var overviewShortcuts: [OverviewShortcut] {
    [
      OverviewShortcut(
        id: "profiles",
        title: L10n.string("nav.profiles", "Profiles"),
        subtitle: L10n.string("overview.shortcuts.profiles", "Import, edit, and save bundles."),
        icon: "rectangle.stack.fill"
      ) { onOpenProfiles?() },
      OverviewShortcut(
        id: "dns",
        title: L10n.string("page.dns", "DNS"),
        subtitle: L10n.string("overview.shortcuts.dns", "Inspect Fake DNS settings."),
        icon: "network"
      ) { onOpenRuntime?(.dns) },
      OverviewShortcut(
        id: "logs",
        title: L10n.string("page.logs", "Logs"),
        subtitle: L10n.string("overview.shortcuts.logs", "Read runtime events."),
        icon: "list.bullet.rectangle.portrait"
      ) { onOpenRuntime?(.logs) },
      OverviewShortcut(
        id: "core",
        title: L10n.string("page.core", "Core"),
        subtitle: L10n.string("overview.shortcuts.core", "Inspect startup phase and backend details."),
        icon: "bolt.shield"
      ) { onOpenMore?(.core) },
      OverviewShortcut(
        id: "settings",
        title: L10n.string("page.settings", "Settings"),
        subtitle: L10n.string("overview.shortcuts.settings", "Open export and advanced tools."),
        icon: "gearshape"
      ) { onOpenMore?(.settings) }
    ]
  }

  private var heroStatusSubtitle: String {
    if !presentation.state.hasProxyNodes {
      return L10n.string("overview.hero.empty_subtitle", "Import a subscription to prepare the iOS tunnel.")
    }
    return "\(activeProxySummary) · \(DisplayValue.mode(presentation.state.runtimeMode))"
  }

  private var primaryHeroActionTitle: String {
    if presentation.state.runtimeState == .running {
      return L10n.string("action.disconnect", "Disconnect")
    }
    if !presentation.state.hasProxyNodes {
      return L10n.string("action.import_config", "Import Subscription")
    }
    return L10n.string("action.connect", "Connect")
  }

  private var primaryHeroActionIcon: String {
    if presentation.state.runtimeState == .running {
      return "stop.fill"
    }
    if !presentation.state.hasProxyNodes {
      return "square.and.arrow.down"
    }
    return "play.fill"
  }

  private var currentProfileSummary: String {
    presentation.state.currentProfileSummary
  }

  private var activeProxySummary: String {
    presentation.state.activeProxySummary
  }

  private var runtimePhaseSummary: String {
    presentation.state.runtimePhaseSummary
  }

  private var runtimePhaseTint: Color {
    switch presentation.state.runtimeState {
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

  private var vpnConnected: Bool {
    presentation.state.vpnConnected
  }

  private var dataPlaneReady: Bool {
    presentation.state.dataPlaneReady
  }

  private var vpnSummary: String {
    vpnConnected
      ? L10n.string("runtime.summary.vpn_connected", "Connected")
      : L10n.string("runtime.summary.vpn_waiting", "Waiting")
  }

  private var dataPlaneSummary: String {
    dataPlaneReady
      ? L10n.string("runtime.summary.data_plane_ready", "Ready")
      : L10n.string("runtime.summary.data_plane_warming", "Warming")
  }

  private var trafficSummary: String {
    presentation.state.trafficSummary
  }

  private var planStartupMessage: String {
    presentation.state.planStartupMessage
  }

  private var diagnosticStartupMessage: String {
    presentation.state.diagnosticStartupMessage
  }

  private var shouldShowStartupDiagnostics: Bool {
    presentation.state.shouldShowStartupDiagnostics
  }

  private var lastFailureReason: String? {
    presentation.state.lastFailureReason
  }

  private var lastFailurePhase: String? {
    presentation.state.lastFailurePhase
  }

  private var lastStopReason: String? {
    presentation.state.lastStopReason
  }

}

struct ProfilesPage: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: ProfilesPresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void

  init(viewModel: ConsoleViewModel, onImportRequested: @escaping (ImportedConfigKind) -> Void) {
    self.viewModel = viewModel
    self.onImportRequested = onImportRequested
    presentation = viewModel.profilesPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("profiles.current.title", "Current Workspace"),
        subtitle: L10n.string(
          "profiles.current.subtitle",
          "The active bundle, editors, and profile library all live here."
        ),
        trailing: AnyView(
          Button(L10n.string("profiles.save", "Save Profile")) {
            viewModel.saveCurrentProfile()
          }
          .buttonStyle(ApplePrimaryButtonStyle())
        )
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ValueRow(
            title: L10n.string("profiles.current.active_profile", "Active Profile"),
            value: presentation.state.currentProfileDisplayName
          )
          ValueRow(
            title: L10n.string("profiles.current.saved_count", "Saved Bundles"),
            value: "\(presentation.state.savedProfiles.count)"
          )
          ValueRow(
            title: L10n.string("profiles.current.last_export", "Last Export"),
            value: presentation.state.lastExportPath ?? L10n.string("common.none", "None")
          )
          if let lastRemoteImportSource = presentation.state.lastRemoteImportSource {
            ValueRow(
              title: L10n.string("profiles.current.last_remote", "Last Remote Import"),
              value: lastRemoteImportSource
            )
          }

          TextField(L10n.string("profiles.field.profile_name", "Profile name"), text: draftProfileNameBinding)
            .appleTextField()
        }
      }

      AppSurface(
        title: L10n.string("profiles.library.title", "Profile Library"),
        subtitle: L10n.string("profiles.library.subtitle", "Saved compatibility bundles ready to load back into the editor.")
      ) {
        if presentation.state.savedProfiles.isEmpty {
          EmptyStateCard(
            icon: "tray",
            title: L10n.string("profiles.library.empty_title", "No saved profiles"),
            message: L10n.string("profiles.library.empty_message", "Save the current bundle to build a reusable profile library.")
          )
        } else {
          AppGroupedList {
            let profiles = presentation.state.savedProfiles
            let lastProfileID = profiles.last?.id
            ForEach(profiles) { profile in
              ProfileLibraryRow(
                profile: profile,
                onLoad: { viewModel.loadProfile(profile) },
                onDelete: { viewModel.deleteProfile(profile) }
              )
              if profile.id != lastProfileID {
                AppListDivider(leadingInset: 60)
              }
            }
          }
        }
      }

      AppSurface(
        title: L10n.string("profiles.remote.title", "Remote Subscription"),
        subtitle: L10n.string(
          "profiles.remote.subtitle",
          "Paste a Clash or Mihomo subscription URL and download the latest YAML into the editor."
        )
      ) {
        VStack(alignment: .leading, spacing: 12) {
          remoteURLInputRow

          Text(L10n.string(
            "profiles.remote.hint",
            "Compatible with direct Clash YAML endpoints and converter-style subscription URLs."
          ))
          .font(.footnote)
          .foregroundStyle(.secondary)

          Button {
            runRemotePrimaryAction()
          } label: {
            Label(
              remotePrimaryActionTitle,
              systemImage: remotePrimaryActionIcon
            )
            .font(.headline)
            .frame(maxWidth: .infinity)
            .frame(minHeight: 48)
          }
          .buttonStyle(ApplePrimaryButtonStyle())
          .disabled(presentation.state.isBusy)

          Button {
            viewModel.restoreDefaultRemoteProfileURL()
          } label: {
            Label(
              L10n.string("profiles.remote.use_default", "Use Default"),
              systemImage: "arrow.counterclockwise"
            )
          }
          .buttonStyle(AppleSecondaryButtonStyle())
          .font(.footnote.weight(.semibold))
        }
      }

      AppSurface(
        title: L10n.string("profiles.imports.title", "Import Sources"),
        subtitle: L10n.string(
          "profiles.imports.subtitle",
          "Bring desktop-compatible text files directly into the editing workspace."
        )
      ) {
        LazyVGrid(columns: actionColumns, spacing: 12) {
          ActionTile(
            title: L10n.string("profiles.imports.profile_yaml", "Import Profile YAML"),
            icon: "doc.text",
            tint: AppPalette.accent
          ) {
            onImportRequested(.profileYAML)
          }

          ActionTile(
            title: L10n.string("profiles.imports.controlled_yaml", "Import Controlled YAML"),
            icon: "slider.horizontal.3",
            tint: AppPalette.warning
          ) {
            onImportRequested(.controlledYAML)
          }

          ActionTile(
            title: L10n.string("action.validate", "Validate"),
            icon: "checkmark.shield",
            tint: AppPalette.warning
          ) {
            viewModel.validateOnly()
          }

          ActionTile(
            title: L10n.string("action.persist_bundle", "Persist Bundle"),
            icon: "square.and.arrow.down.on.square",
            tint: AppPalette.success,
            prominent: true
          ) {
            viewModel.importConfig()
          }
        }
      }

      AppSurface(
        title: L10n.string("profiles.templates.title", "Protocol Templates"),
        subtitle: L10n.string(
          "profiles.templates.subtitle",
          "Append a starter node block to the current profile editor. The embedded Mihomo core consumes these protocols directly."
        )
      ) {
        VStack(alignment: .leading, spacing: 14) {
          LazyVGrid(columns: actionColumns, spacing: 12) {
            ForEach(ProxyTemplatePreset.allCases) { preset in
              ActionTile(
                title: preset.title,
                icon: preset.icon,
                subtitle: preset.subtitle,
                tint: preset == .vlessRealityVision ? AppPalette.warning : AppPalette.accent
              ) {
                viewModel.appendProtocolTemplate(preset)
              }
            }
          }

          LazyVGrid(columns: badgeColumns, alignment: .leading, spacing: 8) {
            TagBadge(title: "VLESS", tint: AppPalette.warning)
            TagBadge(title: "VMess", tint: AppPalette.accent)
            TagBadge(title: "Trojan", tint: AppPalette.success)
            TagBadge(title: "Shadowsocks", tint: AppPalette.accent)
            TagBadge(title: "SOCKS5", tint: AppPalette.warning)
            TagBadge(title: "HTTP", tint: AppPalette.success)
            TagBadge(title: "XTLS", tint: AppPalette.warning)
            TagBadge(title: "Reality", tint: AppPalette.accent)
          }

          Text(L10n.string(
            "profiles.templates.xtls_note",
            "VLESS templates keep XTLS / Reality fields intact so the iOS app can pass them straight through to Mihomo."
          ))
          .font(.footnote)
          .foregroundStyle(.secondary)
        }
      }

      if presentation.state.shouldCollapseProfileEditor {
        AppSurface(
          title: L10n.string("profiles.editor.profile_yaml_title", "Profile YAML"),
          subtitle: L10n.string(
            "profiles.editor.profile_yaml_collapsed",
            "Large profiles stay folded by default so node previews and page navigation remain responsive."
          )
        ) {
          VStack(alignment: .leading, spacing: 12) {
            ValueRow(
              title: L10n.string("profiles.editor.profile_size", "Profile Size"),
              value: DisplayValue.bytes(Int64(presentation.state.profileByteCount))
            )
            ValueRow(
              title: L10n.string("overview.metrics.proxies", "Proxy Nodes"),
              value: "\(presentation.state.proxyCount)"
            )
            ValueRow(
              title: L10n.string("overview.metrics.rules", "Rules"),
              value: "\(presentation.state.ruleCount)"
            )
            if let lastRemoteImportSource = presentation.state.lastRemoteImportSource, !lastRemoteImportSource.isEmpty {
              ValueRow(
                title: L10n.string("profiles.current.last_remote", "Last Remote Import"),
                value: lastRemoteImportSource
              )
            }
            Button(L10n.string("profiles.editor.expand_profile_yaml", "Expand Raw YAML Editor")) {
              viewModel.expandProfileEditor()
            }
            .buttonStyle(ApplePrimaryButtonStyle())
          }
        }
      } else {
        VStack(alignment: .leading, spacing: 12) {
          if presentation.state.isLargeProfile {
            Button(L10n.string("profiles.editor.collapse_profile_yaml", "Hide Raw YAML Editor")) {
              viewModel.collapseProfileEditor()
            }
            .buttonStyle(AppleUtilityButtonStyle())
          }

          EditorSurface(
            title: L10n.string("profiles.editor.profile_yaml_title", "Profile YAML"),
            prompt: L10n.string("profiles.editor.profile_yaml_prompt", "Desktop-compatible profile content."),
            text: profileYamlBinding,
            minHeight: 220
          )
        }
      }

      EditorSurface(
        title: L10n.string("profiles.editor.controlled_yaml_title", "Controlled Mihomo YAML"),
        prompt: L10n.string("profiles.editor.controlled_yaml_prompt", "TUN, DNS, and runtime control overlay."),
        text: controlledConfigBinding,
        minHeight: 220
      )

      AppSurface(
        title: L10n.string("backups.title", "Local Backups"),
        subtitle: L10n.string("backups.subtitle", "Snapshot the current bundle and restore it later without leaving the device.")
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
              TextField(L10n.string("backups.field.name", "Backup name"), text: draftBackupNameBinding)
                .appleTextField()
              Button(L10n.string("backups.create", "Create Backup")) { viewModel.createBackup() }
                .buttonStyle(ApplePrimaryButtonStyle())
            }

            VStack(alignment: .leading, spacing: 10) {
              TextField(L10n.string("backups.field.name", "Backup name"), text: draftBackupNameBinding)
                .appleTextField()
              Button(L10n.string("backups.create", "Create Backup")) { viewModel.createBackup() }
                .buttonStyle(ApplePrimaryButtonStyle())
            }
          }

          if presentation.state.backups.isEmpty {
            EmptyStateCard(
              icon: "archivebox",
              title: L10n.string("backups.empty_title", "No backups yet"),
              message: L10n.string("backups.empty_message", "Create a local snapshot before testing risky runtime changes.")
            )
        } else {
            AppGroupedList {
              let backups = presentation.state.backups
              let lastBackupID = backups.last?.id
              ForEach(backups) { backup in
                BackupListRow(
                  backup: backup,
                  onRestore: { viewModel.restoreBackup(backup) },
                  onDelete: { viewModel.deleteBackup(backup) }
                )
                if backup.id != lastBackupID {
                  AppListDivider(leadingInset: 60)
                }
              }
            }
          }
        }
      }
    }
    .navigationTitle(L10n.string("nav.profiles", "Profiles"))
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Button(L10n.string("action.refresh", "Refresh")) {
          viewModel.refresh(forceControllerSnapshotRefresh: true)
        }
      }
    }
  }

  private var actionColumns: [GridItem] {
    layoutMetrics.flexibleColumns(minimum: 158, maximumCount: 3, spacing: 12, inSurface: true)
  }

  private var badgeColumns: [GridItem] {
    layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 78 : 92, spacing: 8)
  }

  private var remoteProfileURLIsBlank: Bool {
    presentation.state.remoteProfileURLIsBlank
  }

  private var remotePrimaryActionTitle: String {
    remoteProfileURLIsBlank
      ? L10n.string("profiles.remote.paste_and_import", "Paste & Download")
      : L10n.string("profiles.remote.download", "Download Config")
  }

  private var remotePrimaryActionIcon: String {
    remoteProfileURLIsBlank ? "doc.on.clipboard" : "arrow.down.doc.fill"
  }

  private var remoteURLInputRow: some View {
    HStack(spacing: 10) {
      Image(systemName: "link")
        .appFont(size: 16, weight: .semibold)
        .foregroundStyle(AppPalette.accent)
        .frame(width: 30, height: 30)

      TextField(
        L10n.string("profiles.remote.field.url", "Subscription URL"),
        text: remoteProfileURLBinding,
        prompt: Text(L10n.string("profiles.remote.placeholder", "https://example.com/sub?target=clash"))
      )
      .textInputAutocapitalization(.never)
      .autocorrectionDisabled()
      .keyboardType(.URL)
      .appFont(size: 16, weight: .regular)
      .tracking(-0.24)
      .submitLabel(.go)
      .onSubmit {
        if !remoteProfileURLIsBlank {
          viewModel.importRemoteProfile()
        }
      }

      Button {
        viewModel.pasteRemoteProfileURL()
      } label: {
        Image(systemName: "doc.on.clipboard")
          .appFont(size: 16, weight: .semibold)
          .frame(width: 34, height: 34)
      }
      .buttonStyle(.plain)
      .foregroundStyle(AppPalette.accent)
      .accessibilityLabel(L10n.string("profiles.remote.paste", "Paste URL"))
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 10)
    .frame(minHeight: 52)
    .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
  }

  private func runRemotePrimaryAction() {
    if remoteProfileURLIsBlank {
      viewModel.pasteRemoteProfileURL(importImmediately: true)
    } else {
      viewModel.importRemoteProfile()
    }
  }

  private var draftProfileNameBinding: Binding<String> {
    Binding(
      get: { presentation.state.draftProfileName },
      set: { viewModel.draftProfileName = $0 }
    )
  }

  private var remoteProfileURLBinding: Binding<String> {
    Binding(
      get: { presentation.state.remoteProfileURL },
      set: { viewModel.remoteProfileURL = $0 }
    )
  }

  private var profileYamlBinding: Binding<String> {
    Binding(
      get: { presentation.state.profileYaml },
      set: { viewModel.profileYaml = $0 }
    )
  }

  private var controlledConfigBinding: Binding<String> {
    Binding(
      get: { presentation.state.controlledConfigYaml },
      set: { viewModel.controlledConfigYaml = $0 }
    )
  }

  private var draftBackupNameBinding: Binding<String> {
    Binding(
      get: { presentation.state.draftBackupName },
      set: { viewModel.draftBackupName = $0 }
    )
  }
}

private struct ProfileLibraryRow: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let profile: ProfileBundleRecord
  let onLoad: () -> Void
  let onDelete: () -> Void

  var body: some View {
    Group {
      if layoutMetrics.isPhoneWidth || layoutMetrics.usesAccessibilityLayout {
        VStack(alignment: .leading, spacing: 12) {
          summary
          actions
        }
      } else {
        HStack(spacing: 12) {
          summary
          Spacer(minLength: 8)
          actions
        }
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .contentShape(Rectangle())
  }

  private var summary: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "rectangle.stack.fill")
        .appFont(size: 16, weight: .semibold)
        .foregroundStyle(AppPalette.accent)
        .frame(width: 36, height: 36)
        .background(AppPalette.accentSoft, in: RoundedRectangle(cornerRadius: 9))
      VStack(alignment: .leading, spacing: 4) {
        Text(profile.name)
          .appFont(size: 16, weight: .semibold)
          .foregroundStyle(AppPalette.ink)
          .fixedSize(horizontal: false, vertical: true)
        if let remoteSource = profile.remoteSource, !remoteSource.isEmpty {
          Text(remoteSource)
            .appFont(size: 13)
            .foregroundStyle(.secondary)
            .lineLimit(3)
        }
        Text(profile.updatedAt.formatted(date: .abbreviated, time: .shortened))
          .appFont(size: 12)
          .foregroundStyle(.tertiary)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private var actions: some View {
    ViewThatFits(in: .horizontal) {
      HStack(spacing: 10) { actionButtons }
      VStack(alignment: .leading, spacing: 8) { actionButtons }
    }
  }

  @ViewBuilder
  private var actionButtons: some View {
    Button(L10n.string("action.load", "Load"), action: onLoad)
      .buttonStyle(AppleUtilityButtonStyle())
    Button(L10n.string("action.delete", "Delete"), role: .destructive, action: onDelete)
      .buttonStyle(AppleUtilityButtonStyle())
  }
}

private struct BackupListRow: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let backup: BackupRecord
  let onRestore: () -> Void
  let onDelete: () -> Void

  var body: some View {
    Group {
      if layoutMetrics.isPhoneWidth || layoutMetrics.usesAccessibilityLayout {
        VStack(alignment: .leading, spacing: 12) {
          summary
          actions
        }
      } else {
        HStack(spacing: 12) {
          summary
          Spacer(minLength: 8)
          actions
        }
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .contentShape(Rectangle())
  }

  private var summary: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "archivebox.fill")
        .appFont(size: 16, weight: .semibold)
        .foregroundStyle(AppPalette.warning)
        .frame(width: 36, height: 36)
        .background(AppPalette.warning.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))
      VStack(alignment: .leading, spacing: 4) {
        Text(backup.name)
          .appFont(size: 16, weight: .semibold)
          .foregroundStyle(AppPalette.ink)
          .fixedSize(horizontal: false, vertical: true)
        Text(backup.createdAt.formatted(date: .abbreviated, time: .shortened))
          .appFont(size: 13)
          .foregroundStyle(.secondary)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private var actions: some View {
    ViewThatFits(in: .horizontal) {
      HStack(spacing: 10) { actionButtons }
      VStack(alignment: .leading, spacing: 8) { actionButtons }
    }
  }

  @ViewBuilder
  private var actionButtons: some View {
    Button(L10n.string("action.restore", "Restore"), action: onRestore)
      .buttonStyle(AppleUtilityButtonStyle())
    Button(L10n.string("action.delete", "Delete"), role: .destructive, action: onDelete)
      .buttonStyle(AppleUtilityButtonStyle())
  }
}

struct ProxiesPage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: ProxyPresentationModel

  init(viewModel: ConsoleViewModel) {
    self.viewModel = viewModel
    presentation = viewModel.proxyPresentation
  }

  var body: some View {
    AppPageContainer {
      summarySection
      proxyGroupsSection
      proxyNodesSection
    }
    .navigationTitle(L10n.string("nav.proxies", "Proxies"))
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Button(L10n.string("action.refresh", "Refresh")) {
          viewModel.refresh(forceControllerSnapshotRefresh: true)
        }
      }
    }
  }

  private var summarySection: some View {
    AppSurface(
      title: L10n.string("proxies.summary.title", "Node Control"),
      subtitle: L10n.string(
        "proxies.summary.subtitle",
        "Confirm runtime mode and DNS state before switching a group."
      )
    ) {
      VStack(alignment: .leading, spacing: 12) {
        ValueRow(title: L10n.string("runtime.summary.mode", "Mode"), value: DisplayValue.mode(presentation.state.runtimeMode))
        ValueRow(title: L10n.string("runtime.summary.fake_dns", "Fake DNS"), value: DisplayValue.bool(presentation.state.fakeDnsEnabled))
        ValueRow(title: L10n.string("runtime.summary.backend", "Backend"), value: DisplayValue.fallback(presentation.state.backend))
      }
    }
  }

  @ViewBuilder
  private var proxyGroupsSection: some View {
    if presentation.state.displayedGroups.isEmpty {
      EmptyStateCard(
        icon: "point.3.connected.trianglepath.dotted",
        title: L10n.string("proxies.empty_title", "No proxy groups"),
        message: L10n.string("proxies.empty_message", "Import a profile bundle to populate group selections.")
      )
    } else {
      AppSurface(
        title: L10n.string("proxies.groups.title", "Proxy Groups"),
        subtitle: L10n.string(
          "proxies.groups.subtitle",
          "Open a group, test latency, and pin the route you want."
        )
      ) {
        AppGroupedList {
          let groups = presentation.state.displayedGroups
          let lastGroupID = groups.last?.id
          ForEach(groups) { group in
            NavigationLink {
              ProxyGroupDetailPage(viewModel: viewModel, groupName: group.name)
            } label: {
              NodeGroupCard(
                title: group.name,
                selected: presentation.state.proxyGroupDisplaySelection(for: group),
                countLabel: L10n.format("proxies.group.count", "%d nodes", group.all.count),
                icon: "point.3.connected.trianglepath.dotted"
              )
            }
            .buttonStyle(.plain)
            if group.id != lastGroupID {
              AppListDivider(leadingInset: 62)
            }
          }
        }
      }
    }
  }

  @ViewBuilder
  private var proxyNodesSection: some View {
    AppSurface(
      title: L10n.string("proxies.nodes.title", "Subscription Nodes"),
      subtitle: L10n.format(
        "proxies.nodes.subtitle",
        "%d concrete nodes parsed from the active subscription.",
        presentation.state.totalProxyNodeCount
      )
    ) {
      if presentation.state.totalProxyNodeCount == 0 {
        EmptyStateCard(
          icon: "point.3.connected.trianglepath.dotted",
          title: L10n.string("proxies.nodes.empty_title", "No parsed nodes"),
          message: L10n.string("proxies.nodes.empty_message", "Import a subscription or manual YAML profile to inspect concrete proxy nodes here.")
        )
      } else {
        LazyVStack(alignment: .leading, spacing: 12) {
          ProxyNodeSortControl(selection: sortModeBinding)

          AppGroupedList {
            let nodes = presentation.state.displayedNodes
            let lastNodeID = nodes.last?.id
            ForEach(nodes) { node in
              ProxyNodeSurface(
                node: node,
                delayStatus: presentation.state.proxyDelayStatus(for: node),
                allowsSpeedTest: presentation.state.allowsProxyDelayTesting,
                onSpeedTest: {
                  viewModel.speedTest(node: node)
                }
              )
              if node.id != lastNodeID {
                AppListDivider(leadingInset: 64)
              }
            }
          }

          if let limitMessage = presentation.state.displayedNodeLimitMessage {
            Text(limitMessage)
              .font(.footnote)
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
      }
    }
  }

  private var sortModeBinding: Binding<ProxyNodeSortMode> {
    Binding(
      get: { presentation.state.sortMode },
      set: { viewModel.proxyNodeSortMode = $0 }
    )
  }
}

private struct ProxyGroupDetailPage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: ProxyPresentationModel
  let groupName: String

  init(viewModel: ConsoleViewModel, groupName: String) {
    self.viewModel = viewModel
    presentation = viewModel.proxyPresentation
    self.groupName = groupName
  }

  var body: some View {
    AppPageContainer {
      if let group {
        let selectedProxyName = presentation.state.proxyGroupDisplaySelection(for: group)
        ProxyGroupSurface(
          group: group,
          subtitle: presentation.state.proxyGroupDetailStatus(for: group),
          selectedProxyName: selectedProxyName,
          allowsSelection: presentation.state.allowsProxySelection(for: group),
          selectionHint: presentation.state.proxySelectionHint(for: group),
          selectedDelayStatus: presentation.state.proxyDelayStatus(forSelectedProxyIn: group, selectedProxyName: selectedProxyName),
          isSpeedTesting: presentation.state.isSpeedTesting(group: group),
          sortedOptions: presentation.state.sortedOptions(for: group),
          sortMode: sortModeBinding,
          optionDelayStatus: presentation.state.proxyDelayStatus(for:)
        ) { option in
          viewModel.selectProxy(group: group, proxy: option)
        }
      } else {
        EmptyStateCard(
          icon: "point.3.connected.trianglepath.dotted",
          title: L10n.string("proxies.group.missing_title", "Proxy group unavailable"),
          message: L10n.string(
            "proxies.group.missing_message",
            "Refresh the runtime snapshot and open this group again."
          )
        )
      }
    }
    .navigationTitle(groupName)
    .navigationBarTitleDisplayMode(.inline)
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        if let group {
          Button(
            presentation.state.isSpeedTesting(group: group)
              ? L10n.string("proxies.delay.testing", "Testing...")
              : L10n.string("proxies.delay.test_all", "Test All")
          ) {
            viewModel.speedTest(group: group)
          }
          .disabled(!presentation.state.allowsProxyDelayTesting || presentation.state.isSpeedTesting(group: group))
        }
      }
    }
  }

  private var group: ProxyGroupSnapshot? {
    presentation.state.proxyGroup(named: groupName) ?? viewModel.proxyGroup(named: groupName)
  }

  private var sortModeBinding: Binding<ProxyNodeSortMode> {
    Binding(
      get: { presentation.state.sortMode },
      set: { viewModel.proxyNodeSortMode = $0 }
    )
  }
}

private struct ProxyGroupSurface: View {
  let group: ProxyGroupSnapshot
  let subtitle: String
  let selectedProxyName: String
  let allowsSelection: Bool
  let selectionHint: String?
  let selectedDelayStatus: ProxyDelayStatus?
  let isSpeedTesting: Bool
  let sortedOptions: [ProxyOptionPresentationRecord]
  @Binding var sortMode: ProxyNodeSortMode
  let optionDelayStatus: (String) -> ProxyDelayStatus?
  let onSelect: (String) -> Void

  var body: some View {
    AppSurface(
      title: L10n.string("proxies.group.detail.title", "Selection"),
      subtitle: subtitle
    ) {
      if sortedOptions.isEmpty {
        VStack(alignment: .leading, spacing: 12) {
          ProxyGroupSummaryStrip(
            group: group,
            selectedProxyName: selectedProxyName,
            selectedDelayStatus: selectedDelayStatus,
            isSpeedTesting: isSpeedTesting
          )
          Text(
            L10n.string(
              "proxies.group.preview_pending",
              "Options are still loading from the runtime controller. Use Test All to warm provider-backed groups while this list becomes available."
            )
          )
          .font(.footnote)
          .foregroundStyle(.secondary)
        }
      } else {
        VStack(alignment: .leading, spacing: 16) {
          ProxyGroupSummaryStrip(
            group: group,
            selectedProxyName: selectedProxyName,
            selectedDelayStatus: selectedDelayStatus,
            isSpeedTesting: isSpeedTesting
          )

          if let selectionHint {
            ProxyGroupNotice(message: selectionHint)
          }

          VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
              Text(L10n.string("proxies.group.options.title", "Selectable Nodes"))
                .font(.subheadline.weight(.semibold))
              Spacer(minLength: 8)
              Text(L10n.format("proxies.group.options.count", "%d options", sortedOptions.count))
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            ProxyNodeSortControl(selection: $sortMode)

            AppGroupedList {
              let lastOptionID = sortedOptions.last?.id
              ForEach(sortedOptions) { option in
                ProxyOptionRow(
                  name: option.name,
                  isSelected: option.name == selectedProxyName,
                  delayStatus: optionDelayStatus(option.name),
                  allowsSelection: allowsSelection
                ) {
                  onSelect(option.name)
                }
                if option.id != lastOptionID {
                  AppListDivider(leadingInset: 58)
                }
              }
            }
          }
        }
      }
    }
  }
}

private struct ProxyGroupSummaryStrip: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let group: ProxyGroupSnapshot
  let selectedProxyName: String
  let selectedDelayStatus: ProxyDelayStatus?
  let isSpeedTesting: Bool

  var body: some View {
    LazyVGrid(columns: layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 126 : 142, spacing: 10), spacing: 10) {
      StatusInfoChip(
        title: L10n.string("proxies.group.selection", "Selection"),
        value: DisplayValue.fallback(selectedProxyName),
        icon: "checkmark.circle.fill",
        tint: AppPalette.success
      )
      StatusInfoChip(
        title: L10n.string("proxies.group.type", "Type"),
        value: groupTypeLabel,
        icon: "switch.2",
        tint: AppPalette.accent
      )
      StatusInfoChip(
        title: L10n.string("proxies.group.delay", "Delay"),
        value: delayLabel,
        icon: "speedometer",
        tint: delayTint
      )
      StatusInfoChip(
        title: L10n.string("proxies.group.option_count", "Options"),
        value: "\(group.displayOptions.count)",
        icon: "list.bullet",
        tint: AppPalette.warning
      )
    }
  }

  private var groupTypeLabel: String {
    let rawType = group.type?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .replacingOccurrences(of: "-", with: " ")
      ?? ""
    return rawType.isEmpty ? L10n.string("common.unknown", "Unknown") : rawType.uppercased()
  }

  private var delayLabel: String {
    if isSpeedTesting {
      return L10n.string("proxies.delay.testing", "Testing...")
    }

    guard let selectedDelayStatus else {
      return L10n.string("proxies.delay.not_tested", "Not tested")
    }

    return selectedDelayStatus.label
  }

  private var delayTint: Color {
    if isSpeedTesting {
      return AppPalette.warning
    }
    return selectedDelayStatus?.tint ?? AppPalette.accent
  }
}

private struct ProxyGroupNotice: View {
  let message: String

  var body: some View {
    HStack(alignment: .top, spacing: 10) {
      Image(systemName: "info.circle.fill")
        .font(.subheadline.weight(.semibold))
        .foregroundStyle(AppPalette.accent)
      Text(message)
        .appFont(size: 14, weight: .regular)
        .tracking(-0.18)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
    .padding(14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
  }
}

private struct ProxyNodeSortControl: View {
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize
  @Binding var selection: ProxyNodeSortMode

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(L10n.string("proxies.sort.title", "Sort"))
        .appFont(size: 14, weight: .semibold)
        .tracking(-0.18)
        .foregroundStyle(.secondary)
      if dynamicTypeSize.isAccessibilitySize {
        sortPicker.pickerStyle(.menu)
      } else {
        sortPicker.pickerStyle(.segmented)
      }
    }
    .accessibilityLabel(L10n.string("proxies.sort.title", "Sort"))
  }

  private var sortPicker: some View {
    Picker(L10n.string("proxies.sort.title", "Sort"), selection: $selection) {
      ForEach(ProxyNodeSortMode.allCases) { mode in
        Text(mode.title).tag(mode)
      }
    }
  }
}

private struct ProxyOptionRow: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let name: String
  let isSelected: Bool
  let delayStatus: ProxyDelayStatus?
  let allowsSelection: Bool
  let onSelect: () -> Void

  var body: some View {
    Button {
      onSelect()
    } label: {
      HStack(alignment: .center, spacing: 12) {
        Image(systemName: leadingIcon)
          .appFont(size: 20, weight: .semibold)
          .foregroundStyle(leadingTint)
          .frame(width: 30, height: 30)

        VStack(alignment: .leading, spacing: 4) {
          Text(name)
            .appFont(size: 15, weight: isSelected ? .semibold : .regular)
            .tracking(-0.18)
            .foregroundStyle(AppPalette.ink)
            .lineLimit(layoutMetrics.usesAccessibilityLayout ? nil : 3)
            .fixedSize(horizontal: false, vertical: true)
            .multilineTextAlignment(.leading)
          Text(stateLabel)
            .appFont(size: 12, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(.secondary)
        }

        Spacer(minLength: 8)

        if let delayStatus {
          ProxyDelayBadge(status: delayStatus)
        } else {
          TagBadge(
            title: L10n.string("proxies.delay.not_tested", "Not tested"),
            tint: Color(uiColor: .secondaryLabel)
          )
        }
      }
      .padding(.horizontal, 14)
      .padding(.vertical, 12)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(rowBackground)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .disabled(!allowsSelection)
  }

  private var leadingIcon: String {
    if isSelected {
      return "checkmark.circle.fill"
    }
    return allowsSelection ? "circle" : "lock.circle"
  }

  private var leadingTint: Color {
    if isSelected {
      return AppPalette.accent
    }
    return allowsSelection ? AppPalette.inkMuted : AppPalette.warning
  }

  private var stateLabel: String {
    if isSelected {
      return L10n.string("proxies.group.option.selected", "Selected for this group")
    }
    if allowsSelection {
      return L10n.string("proxies.group.option.tap", "Tap to pin this node")
    }
    return L10n.string("proxies.group.option.locked", "Managed by the runtime")
  }

  private var rowBackground: Color {
    isSelected
      ? AppPalette.accentSoft
      : Color.clear
  }

}

private extension ProxyNodeSortMode {
  var title: String {
    switch self {
    case .profileOrder:
      return L10n.string("proxies.sort.profile_order", "Profile Order")
    case .latency:
      return L10n.string("proxies.sort.latency", "Latency")
    }
  }
}

private struct ProxyNodeSurface: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let node: ProxyNodeRecord
  let delayStatus: ProxyDelayStatus?
  let allowsSpeedTest: Bool
  let onSpeedTest: () -> Void

  var body: some View {
    ViewThatFits(in: .horizontal) {
      horizontalLayout
      verticalLayout
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }

  private var horizontalLayout: some View {
    HStack(alignment: .top, spacing: 12) {
      iconView
      contentView

      Spacer(minLength: 8)

      testButton
    }
  }

  private var verticalLayout: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(alignment: .top, spacing: 12) {
        iconView
        contentView
      }
      testButton
    }
  }

  private var iconView: some View {
    Image(systemName: "server.rack")
      .appFont(size: 16, weight: .semibold)
      .foregroundStyle(AppPalette.accent)
      .frame(width: 36, height: 36)
      .background(AppPalette.accentSoft, in: Circle())
  }

  private var contentView: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(node.name)
        .appFont(size: 16, weight: .semibold)
        .tracking(-0.24)
        .foregroundStyle(AppPalette.ink)
        .lineLimit(2)
      Text(endpointValue)
        .appFont(size: 13, weight: .regular)
        .tracking(-0.12)
        .foregroundStyle(.secondary)
        .lineLimit(2)

      LazyVGrid(columns: layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 64 : 74, spacing: 7), alignment: .leading, spacing: 7) {
        if let delayStatus {
          ProxyDelayBadge(status: delayStatus)
        }
        if !node.type.isEmpty {
          TagBadge(title: node.type.uppercased(), tint: AppPalette.accent)
        }
        if node.udp {
          TagBadge(title: "UDP", tint: AppPalette.accent)
        }
        if node.tls {
          TagBadge(title: "TLS", tint: AppPalette.warning)
        }
        if !node.network.isEmpty {
          TagBadge(title: node.network.uppercased(), tint: AppPalette.accent)
        }
        if !node.security.isEmpty {
          TagBadge(title: node.security.uppercased(), tint: AppPalette.warning)
        }
      }
    }
  }

  private var testButton: some View {
    Button(testButtonTitle) {
      onSpeedTest()
    }
    .buttonStyle(AppleUtilityButtonStyle())
    .disabled(!allowsSpeedTest || isTestingDelay)
  }

  private var endpointValue: String {
    let host = DisplayValue.fallback(node.server)
    let port = node.port.isEmpty ? "" : ":\(node.port)"
    return "\(host)\(port)"
  }

  private var isTestingDelay: Bool {
    if case .testing? = delayStatus {
      return true
    }
    return false
  }

  private var testButtonTitle: String {
    isTestingDelay
      ? L10n.string("proxies.delay.testing", "Testing...")
      : L10n.string("proxies.delay.test", "Test")
  }
}

private struct ProxyDelayBadge: View {
  let status: ProxyDelayStatus

  var body: some View {
    TagBadge(title: status.label, tint: status.tint)
  }
}

private extension ProxyDelayStatus {
  var label: String {
    switch self {
    case .testing:
      return L10n.string("proxies.delay.testing", "Testing...")
    case .available(let delay):
      return "\(delay) ms"
    case .controllerUnavailable:
      return L10n.string("proxies.delay.controller_offline", "Controller Offline")
    case .unavailable:
      return L10n.string("proxies.delay.unavailable", "Timeout")
    }
  }

  var tint: Color {
    switch self {
    case .testing:
      return AppPalette.warning
    case .available(let delay):
      if delay <= 150 {
        return AppPalette.success
      }
      if delay <= 350 {
        return AppPalette.warning
      }
      return AppPalette.danger
    case .controllerUnavailable:
      return AppPalette.warning
    case .unavailable:
      return AppPalette.danger
    }
  }
}

struct RuntimeHubPage: View {
  var body: some View {
    AppPageContainer {
      AppPageHeader(
        title: L10n.string("runtime.hub.title", "Runtime"),
        subtitle: L10n.string(
          "runtime.hub.subtitle",
          "Rules, DNS, logs, and live connections are grouped here for network-level inspection."
        ),
        icon: "bolt.shield"
      )

      AppGroupedList {
        let destinations = RuntimeDestination.allCases
        let lastDestinationID = destinations.last?.id
        ForEach(destinations) { destination in
          NavigationLink(value: destination) {
            AppNavigationListRow(title: destination.title, subtitle: destination.subtitle, icon: destination.icon)
          }
          .buttonStyle(.plain)
          if destination.id != lastDestinationID {
            AppListDivider(leadingInset: 60)
          }
        }
      }
    }
    .navigationTitle(L10n.string("nav.runtime", "Runtime"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

struct MoreHubPage: View {
  var body: some View {
    AppPageContainer {
      AppPageHeader(
        title: L10n.string("more.hub.title", "More"),
        subtitle: L10n.string(
          "more.hub.subtitle",
          "Profiles, diagnostics, and advanced tools stay here so Home remains focused on connect and switch."
        ),
        icon: "square.grid.2x2"
      )

      MoreDestinationSection(
        title: L10n.string("more.section.primary", "Primary"),
        destinations: [.profiles, .ruleInsight, .settings]
      )
      MoreDestinationSection(
        title: L10n.string("more.section.diagnostics", "Diagnostics"),
        destinations: [.dns, .rules, .connections, .logs]
      )
      MoreDestinationSection(
        title: L10n.string("more.section.advanced", "Advanced"),
        destinations: [.resources, .core, .override]
      )
    }
    .navigationTitle(L10n.string("nav.more", "More"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

private struct MoreDestinationSection: View {
  let title: String
  let destinations: [MoreDestination]

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(title)
        .appFont(size: 13, weight: .semibold)
        .tracking(-0.12)
        .foregroundStyle(.secondary)
        .textCase(.uppercase)
        .padding(.horizontal, 4)

      AppGroupedList {
        let lastDestinationID = destinations.last?.id
        ForEach(destinations) { destination in
          NavigationLink(value: AppDestination.more(destination)) {
            AppNavigationListRow(title: destination.title, subtitle: destination.subtitle, icon: destination.icon)
          }
          .buttonStyle(.plain)
          if destination.id != lastDestinationID {
            AppListDivider(leadingInset: 60)
          }
        }
      }
    }
  }
}

struct RulesPage: View {
  @ObservedObject private var viewModel: ConsoleViewModel
  @ObservedObject private var presentation: RulesPresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void

  init(viewModel: ConsoleViewModel, onImportRequested: @escaping (ImportedConfigKind) -> Void) {
    self.viewModel = viewModel
    presentation = viewModel.rulesPresentation
    self.onImportRequested = onImportRequested
  }

  var body: some View {
    AppPageContainer {
      AppSurface(title: L10n.string("routing.title", "Internet Routing"), subtitle: L10n.string("routing.description", "General routing proxies overseas services and unmatched traffic, while keeping common domestic services and the local network direct.")) {
        VStack(alignment: .leading, spacing: 14) {
          Picker(L10n.string("routing.policy", "Routing Policy"), selection: Binding(get: { viewModel.routingPolicy }, set: { viewModel.setRoutingPolicy($0) })) {
            ForEach(IOSRoutingPolicy.allCases) { policy in Text(policy.title).tag(policy) }
          }
          .pickerStyle(.menu)
          .disabled(viewModel.isBusy || viewModel.isUpdatingRoutingRules)
          ValueRow(title: L10n.string("routing.effective", "Effective Policy"), value: viewModel.effectiveRoutingPolicy.title)
          Text(L10n.string("routing.automatic_help", "Automatic preserves profile routing and adds general Internet rules when the profile only covers OpenAI."))
            .font(.footnote).foregroundStyle(.secondary)
          if viewModel.effectiveRoutingPolicy == .general {
            Text(L10n.string("routing.cache_help", "Rules are bundled for first use, cached locally, and checked every 24 hours while the VPN is running. Failed updates retain valid caches."))
              .font(.footnote).foregroundStyle(.secondary)
            Button(action: viewModel.refreshGeneralRoutingRules) {
              Label(L10n.string("routing.update", "Update General Rules"), systemImage: "arrow.clockwise")
                .frame(minHeight: 44)
            }
            .disabled(viewModel.isBusy || viewModel.isUpdatingRoutingRules)
          }
          if viewModel.effectiveRoutingPolicy == .desktopSnapshot, let snapshot = viewModel.desktopRoutingSnapshot {
            ValueRow(title: L10n.string("routing.snapshot_count", "Rule Count"), value: String(snapshot.rules.count))
            ValueRow(title: L10n.string("routing.snapshot_date", "Updated At"), value: snapshot.generatedAt)
          }
          Button { onImportRequested(.routingSnapshot) } label: {
            Label(L10n.string("routing.import", "Import Rules"), systemImage: "square.and.arrow.down")
              .frame(minHeight: 44)
          }
          .disabled(viewModel.isBusy || viewModel.isUpdatingRoutingRules)
          Text(L10n.string("routing.snapshot_help", "Domain/IP rules define proxy, direct and block behavior. Imported rule sets use the current device’s nodes and can be reused across devices."))
            .font(.footnote).foregroundStyle(.secondary)
          if let message = viewModel.routingUpdateMessage {
            Text(message).font(.footnote).foregroundStyle(.secondary)
          }
        }
      }

      AppSurface(
        title: L10n.string("rules.summary.title", "Rule Preview"),
        subtitle: L10n.format("rules.summary.subtitle", "%d parsed rules from the effective configuration.", presentation.state.totalCount)
      ) {
        if presentation.state.isEmpty {
          EmptyStateCard(
            icon: "list.number",
            title: L10n.string("rules.empty_title", "No rules parsed"),
            message: L10n.string("rules.empty_message", "The current profile does not expose any parsed rule preview yet.")
          )
        } else {
          AppGroupedList {
            let records = presentation.state.records
            let lastRecordID = records.last?.id
            ForEach(records) { record in
              RulePreviewRow(rule: record.rule)
              if record.id != lastRecordID {
                AppListDivider(leadingInset: 58)
              }
            }
          }
          if presentation.state.hiddenCount > 0 {
            Text(L10n.format("rules.preview_limit", "Showing the first %d rules for a faster preview.", presentation.state.records.count))
              .font(.footnote)
              .foregroundStyle(.secondary)
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.rules", "Rules"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

struct DnsPage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: DnsPresentationModel

  init(viewModel: ConsoleViewModel) {
    self.viewModel = viewModel
    presentation = viewModel.dnsPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("dns.summary.title", "Fake DNS Summary"),
        subtitle: L10n.string(
          "dns.summary.subtitle",
          "Review Fake-IP, upstream DNS and domain resolution policies."
        )
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ValueRow(title: L10n.string("dns.enabled", "Enabled"), value: DisplayValue.bool(presentation.state.summary.enabled))
          ValueRow(title: L10n.string("dns.enhanced_mode", "Enhanced Mode"), value: DisplayValue.fallback(presentation.state.summary.enhancedMode))
          ValueRow(title: L10n.string("dns.fake_ip_range", "Fake IP Range"), value: DisplayValue.fallback(presentation.state.summary.fakeIPRange))
          WrappedValueGroup(title: L10n.string("dns.fake_ip_filter", "Fake IP Filter"), values: presentation.state.summary.fakeIPFilter)
          WrappedValueGroup(title: L10n.string("dns.nameservers", "Nameservers"), values: presentation.state.summary.nameservers)
          WrappedValueGroup(title: L10n.string("dns.proxy_nameservers", "Proxy Nameservers"), values: presentation.state.summary.proxyServerNameservers)
          WrappedValueGroup(title: L10n.string("dns.fallback", "Fallback"), values: presentation.state.summary.fallbackServers)
          WrappedValueGroup(title: L10n.string("dns.policy_keys", "Nameserver Policy Keys"), values: presentation.state.summary.nameserverPolicyKeys)
        }
      }

      EditorSurface(
        title: L10n.string("dns.editor.title", "Controlled Mihomo YAML"),
        prompt: L10n.string("dns.editor.prompt", "Keep dns, fake-ip, and TUN configuration aligned with runtime requirements."),
        text: controlledConfigBinding,
        minHeight: 300
      )
    }
    .navigationTitle(L10n.string("page.dns", "DNS"))
    .navigationBarTitleDisplayMode(.inline)
  }

  private var controlledConfigBinding: Binding<String> {
    Binding(
      get: { presentation.state.controlledConfigYaml },
      set: { viewModel.controlledConfigYaml = $0 }
    )
  }
}

private struct RulePreviewRow: View {
  let rule: RuleMatchRecord

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "list.number")
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(AppPalette.accent)
        .frame(width: 34, height: 34)
        .background(AppPalette.accentSoft, in: RoundedRectangle(cornerRadius: 9, style: .continuous))

      VStack(alignment: .leading, spacing: 4) {
        Text(rule.raw)
          .appFont(size: 13, weight: .regular, design: .monospaced)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(2)
        Text("\(rule.type) -> \(rule.target) · \(rule.payload)")
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
          .lineLimit(2)
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }
}

private struct ConnectionListRow: View {
  let connection: ConnectionSnapshot

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "arrow.left.arrow.right.circle")
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(AppPalette.success)
        .frame(width: 34, height: 34)
        .background(AppPalette.success.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))

      VStack(alignment: .leading, spacing: 4) {
        Text(connection.host)
          .appFont(size: 16, weight: .semibold)
          .tracking(-0.24)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(1)
        Text(L10n.format("connections.chain_rule", "Chain: %@ · Rule: %@", connection.chain, connection.rule))
          .appFont(size: 13, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
          .lineLimit(2)
        Text(L10n.format(
          "connections.traffic",
          "Up %@ · Down %@",
          DisplayValue.bytes(connection.upload),
          DisplayValue.bytes(connection.download)
        ))
        .appFont(size: 12, weight: .regular)
        .tracking(-0.12)
        .foregroundStyle(.tertiary)
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }
}

private struct ResourceListRow: View {
  let resource: ResourceRecord

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "shippingbox")
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(AppPalette.warning)
        .frame(width: 34, height: 34)
        .background(AppPalette.warning.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))

      VStack(alignment: .leading, spacing: 4) {
        Text(resource.name)
          .appFont(size: 16, weight: .semibold)
          .tracking(-0.24)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(1)
        Text("\(resource.kind) · \(DisplayValue.fallback(resource.behavior))")
          .appFont(size: 13, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        if !resource.localStatus.isEmpty {
          Text(resourceStatusLine(resource))
            .appFont(size: 12, weight: .semibold)
            .tracking(-0.12)
            .foregroundStyle(resourceStatusColor(resource.localStatus))
            .lineLimit(2)
        }
        Text(L10n.format("resources.source", "Source: %@", DisplayValue.fallback(resource.source)))
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.tertiary)
          .lineLimit(2)
        Text(L10n.format("resources.path", "Path: %@", DisplayValue.fallback(resource.path)))
          .appFont(size: 12, weight: .regular)
          .tracking(-0.12)
          .foregroundStyle(.tertiary)
          .lineLimit(2)
        if !resource.interval.isEmpty {
          Text(L10n.format("resources.interval", "Interval: %@", resource.interval))
            .appFont(size: 12, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(.tertiary)
        }
        if let lastError = resource.lastError, !lastError.isEmpty {
          Text(lastError)
            .appFont(size: 12, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(AppPalette.danger)
            .lineLimit(2)
        }
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }

  private func resourceStatusLine(_ resource: ResourceRecord) -> String {
    var parts = [resource.localStatus]
    if let localSize = resource.localSize, localSize > 0 {
      parts.append(ByteCountFormatter.string(fromByteCount: localSize, countStyle: .file))
    }
    if let updatedAt = resource.updatedAt {
      parts.append(updatedAt.formatted(date: .abbreviated, time: .shortened))
    }
    return parts.joined(separator: " · ")
  }

  private func resourceStatusColor(_ status: String) -> Color {
    switch status {
    case "ready":
      return AppPalette.success
    case "downloading":
      return AppPalette.warning
    case "failed", "invalid-url", "seed-failed", "unavailable":
      return AppPalette.danger
    default:
      return AppPalette.inkMuted
    }
  }
}

struct ConnectionsPage: View {
  @ObservedObject private var presentation: ConnectionsPresentationModel

  init(viewModel: ConsoleViewModel) {
    presentation = viewModel.connectionsPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("connections.title", "Connections"),
        subtitle: L10n.string("connections.subtitle", "Follow live request chains, rules, and transfer volume.")
      ) {
        if presentation.state.connections.isEmpty {
          EmptyStateCard(
            icon: "arrow.left.arrow.right.circle",
            title: L10n.string("connections.empty_title", "No live connections"),
            message: L10n.string("connections.empty_message", "Connection snapshots will appear here once the runtime handles traffic.")
          )
        } else {
          AppGroupedList {
            let connections = presentation.state.connections
            let lastConnectionID = connections.last?.id
            ForEach(connections) { connection in
              ConnectionListRow(connection: connection)
              if connection.id != lastConnectionID {
                AppListDivider(leadingInset: 58)
              }
            }
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.connections", "Connections"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

struct RuleInsightPage: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: RuleInsightPresentationModel

  init(viewModel: ConsoleViewModel) {
    self.viewModel = viewModel
    presentation = viewModel.ruleInsightPresentation
  }

  var body: some View {
    AppPageContainer {
      let state = presentation.state
      let explanations = state.explanations

      AppSurface(
        title: L10n.string("rule_insight.summary.title", "Route Explanation"),
        subtitle: L10n.string(
          "rule_insight.summary.subtitle",
          "Connect live traffic to the matched rule, proxy chain, final node, and Fake DNS state."
        )
      ) {
        LazyVGrid(columns: summaryColumns, spacing: 10) {
          StatusInfoChip(
            title: L10n.string("runtime.summary.mode", "Mode"),
            value: DisplayValue.mode(state.runtimeMode),
            icon: "switch.2",
            tint: AppPalette.accent
          )
          StatusInfoChip(
            title: L10n.string("rule_insight.summary.fake_dns", "Fake DNS"),
            value: DisplayValue.bool(state.fakeDnsEnabled),
            icon: "network",
            tint: state.fakeDnsEnabled ? AppPalette.success : AppPalette.warning
          )
          StatusInfoChip(
            title: L10n.string("rule_insight.summary.live_connections", "Live Connections"),
            value: "\(state.connectionCount)",
            icon: "arrow.left.arrow.right.circle",
            tint: AppPalette.success
          )
          StatusInfoChip(
            title: L10n.string("rule_insight.summary.proxied", "Proxied"),
            value: "\(state.proxiedCount)",
            icon: "point.topleft.down.curvedto.point.bottomright.up",
            tint: AppPalette.accent
          )
          StatusInfoChip(
            title: L10n.string("rule_insight.summary.route_cost", "Route Cost"),
            value: routeCostText,
            icon: "timer",
            tint: state.metrics.isWithinTarget ? AppPalette.success : AppPalette.warning
          )
        }
      }

      AppSurface(
        title: L10n.string("rule_insight.routes.title", "Why This Node"),
        subtitle: L10n.string(
          "rule_insight.routes.subtitle",
          "Each card explains the route decision for one live request."
        )
      ) {
        if explanations.isEmpty {
          EmptyStateCard(
            icon: "sparkle.magnifyingglass",
            title: L10n.string("rule_insight.empty.title", "No route decisions yet"),
            message: L10n.string(
              "rule_insight.empty.message",
              "Start the VPN and open a website. If this stays empty, pull to refresh or tap Refresh so the app asks the embedded controller for a fresh connection snapshot."
            )
          )
          RuleInsightSnapshotHint(state: state)
        } else {
          if state.usingRecentSnapshot {
            ProxyGroupNotice(
              message: L10n.string(
                "rule_insight.recent_snapshot_notice",
                "Showing the most recent route decisions. Live connections ended before this refresh, so these cards preserve the last controller snapshot instead of going blank."
              )
            )
          }
          AppGroupedList {
            let lastExplanationID = explanations.last?.id
            ForEach(explanations) { explanation in
              RuleInsightCard(explanation: explanation)
              if explanation.id != lastExplanationID {
                AppListDivider(leadingInset: 62)
              }
            }
          }
          VStack(alignment: .leading, spacing: 8) {
            if state.hiddenCount > 0 {
              Text(L10n.format(
                "rule_insight.preview_limit",
                "Showing the first %d live connections for smoother diagnostics.",
                explanations.count
              ))
              .font(.footnote)
              .foregroundStyle(.secondary)
            }
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.rule_insight", "Rule Insight"))
    .navigationBarTitleDisplayMode(.inline)
    .onAppear {
      viewModel.refreshRouteInsight()
    }
    .toolbar {
      ToolbarItem(placement: .topBarTrailing) {
        Button(L10n.string("action.refresh", "Refresh")) {
          viewModel.refreshRouteInsight()
        }
      }
    }
  }

  private var routeCostText: String {
    let metrics = presentation.state.metrics
    guard metrics.sampleCount > 0 else {
      return L10n.string("common.pending", "Pending")
    }
    return String(format: "%.1f ms", metrics.lastDurationMs)
  }

  private var summaryColumns: [GridItem] {
    layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 132 : 154, spacing: 10)
  }
}

private struct RuleInsightSnapshotHint: View {
  let state: RuleInsightPresentationState

  var body: some View {
    AppGroupedList {
      RuleInsightHintRow(
        title: L10n.string("rule_insight.hint.runtime", "Runtime"),
        value: "\(DisplayValue.connectionState(state.runtimeState)) · \(DisplayValue.bool(state.vpnConnected)) VPN",
        icon: "power.circle",
        tint: state.vpnConnected ? AppPalette.success : AppPalette.warning
      )
      AppListDivider(leadingInset: 58)
      RuleInsightHintRow(
        title: L10n.string("rule_insight.hint.controller", "Controller"),
        value: state.controllerAddress ?? L10n.string("common.none", "None"),
        icon: "point.3.connected.trianglepath.dotted",
        tint: controllerTint
      )
      AppListDivider(leadingInset: 58)
      RuleInsightHintRow(
        title: L10n.string("rule_insight.hint.connections", "Connections"),
        value: "\(state.connectionCount)",
        icon: "arrow.left.arrow.right.circle",
        tint: state.connectionCount == 0 ? AppPalette.warning : AppPalette.success
      )
      AppListDivider(leadingInset: 58)
      RuleInsightHintRow(
        title: L10n.string("rule_insight.hint.app_group", "App Group"),
        value: appGroupValue,
        icon: "externaldrive.connected.to.line.below",
        tint: state.sharedStoreDiagnostics.isAvailable ? AppPalette.success : AppPalette.danger
      )
    }
  }

  private var controllerTint: Color {
    let address = state.controllerAddress?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return address.isEmpty ? AppPalette.warning : AppPalette.success
  }

  private var appGroupValue: String {
    if state.sharedStoreDiagnostics.isAvailable {
      return state.sharedStoreDiagnostics.containerPath
        ?? L10n.string("rule_insight.hint.app_group_available", "Available")
    }
    return state.sharedStoreDiagnostics.errorDescription
      ?? L10n.string("rule_insight.hint.app_group_unavailable", "Unavailable")
  }
}

private struct RuleInsightHintRow: View {
  let title: String
  let value: String
  let icon: String
  let tint: Color

  var body: some View {
    HStack(spacing: 12) {
      Image(systemName: icon)
        .appFont(size: 15, weight: .semibold)
        .foregroundStyle(tint)
        .frame(width: 34, height: 34)
        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
      VStack(alignment: .leading, spacing: 3) {
        Text(title)
          .appFont(size: 13, weight: .regular)
          .foregroundStyle(.secondary)
        Text(DisplayValue.fallback(value))
          .appFont(size: 15, weight: .semibold)
          .tracking(-0.18)
          .foregroundStyle(AppPalette.ink)
          .lineLimit(2)
      }
      Spacer(minLength: 0)
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 12)
  }
}

private struct RuleInsightCard: View {
  @Environment(\.appLayoutMetrics) private var layoutMetrics

  let explanation: RouteExplanation

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack(alignment: .top, spacing: 12) {
        Image(systemName: icon)
          .appFont(size: 16, weight: .semibold)
          .foregroundStyle(tint)
          .frame(width: 36, height: 36)
          .background(tint.opacity(0.10), in: Circle())

        VStack(alignment: .leading, spacing: 4) {
          Text(explanation.host)
            .appFont(size: 16, weight: .semibold)
            .tracking(-0.24)
            .foregroundStyle(AppPalette.ink)
            .lineLimit(2)
          Text(explanation.summary)
            .appFont(size: 13, weight: .regular)
            .tracking(-0.12)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
        Spacer(minLength: 0)
      }

      LazyVGrid(columns: layoutMetrics.adaptiveColumns(minimum: layoutMetrics.isNarrowPhone ? 112 : 132, spacing: 8), alignment: .leading, spacing: 8) {
        RouteFactPill(title: L10n.string("rule_insight.card.final_node", "Final Node"), value: explanation.finalNode, tint: tint)
        RouteFactPill(title: L10n.string("rule_insight.card.rule_type", "Rule Type"), value: ruleKindText, tint: AppPalette.accent)
        RouteFactPill(title: L10n.string("rule_insight.card.dns_context", "DNS Context"), value: dnsContextText, tint: dnsTint)
      }

      VStack(alignment: .leading, spacing: 0) {
        RuleInsightDetailRow(
          title: L10n.string("rule_insight.card.matched_rule", "Matched Rule"),
          value: explanation.matchedRuleDisplay
        )
        if !explanation.destinationDisplay.isEmpty {
          AppListDivider(leadingInset: 0)
          RuleInsightDetailRow(
            title: L10n.string("rule_insight.card.destination", "Destination"),
            value: explanation.destinationDisplay
          )
        }
        if !explanation.destinationIPASN.isEmpty {
          AppListDivider(leadingInset: 0)
          RuleInsightDetailRow(
            title: L10n.string("rule_insight.card.destination_asn", "Destination ASN"),
            value: explanation.destinationIPASN
          )
        }
        AppListDivider(leadingInset: 0)
        RuleInsightDetailRow(
          title: L10n.string("rule_insight.card.chain_steps", "Decision Steps"),
          value: explanation.chainStepDisplay
        )
        AppListDivider(leadingInset: 0)
        RuleInsightDetailRow(
          title: L10n.string("rule_insight.card.chain", "Proxy Chain"),
          value: explanation.chainDisplay
        )
        AppListDivider(leadingInset: 0)
        RuleInsightDetailRow(
          title: L10n.string("rule_insight.card.traffic", "Traffic"),
          value: "\(DisplayValue.bytes(explanation.upload)) / \(DisplayValue.bytes(explanation.download))"
        )
      }
      .background(AppPalette.pearl, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }

  private var ruleKindText: String {
    switch explanation.matchedRuleKind {
    case .domain:
      return L10n.string("rule_insight.rule_kind.domain", "Domain")
    case .domainSuffix:
      return L10n.string("rule_insight.rule_kind.domain_suffix", "Domain Suffix")
    case .domainKeyword:
      return L10n.string("rule_insight.rule_kind.domain_keyword", "Domain Keyword")
    case .geoSite:
      return L10n.string("rule_insight.rule_kind.geosite", "GeoSite")
    case .geoIP:
      return L10n.string("rule_insight.rule_kind.geoip", "GeoIP")
    case .ipASN:
      return L10n.string("rule_insight.rule_kind.ip_asn", "IP ASN")
    case .ipCIDR:
      return L10n.string("rule_insight.rule_kind.ip_cidr", "IP CIDR")
    case .ipCIDR6:
      return L10n.string("rule_insight.rule_kind.ip_cidr6", "IPv6 CIDR")
    case .match:
      return L10n.string("rule_insight.rule_kind.match", "Match")
    case .final:
      return L10n.string("rule_insight.rule_kind.final", "Final")
    case .script:
      return L10n.string("rule_insight.rule_kind.script", "Script")
    case .process:
      return L10n.string("rule_insight.rule_kind.process", "Process")
    case .network:
      return L10n.string("rule_insight.rule_kind.network", "Network")
    case .unknown:
      return L10n.string("rule_insight.rule_kind.unknown", "Controller Reported")
    }
  }

  private var dnsContextText: String {
    switch explanation.dnsContext {
    case .fakeIPMapped:
      return L10n.string(
        "rule_insight.dns_context.fake_ip_mapped",
        "Fake DNS mapped fake IP to domain"
      )
    case .sniffedDomain:
      return L10n.string(
        "rule_insight.dns_context.sniffed_domain",
        "Sniffer recovered domain"
      )
    case .metadataDomain:
      return L10n.string(
        "rule_insight.dns_context.metadata_domain",
        "Metadata carried domain"
      )
    case .ipOnly:
      return L10n.string(
        "rule_insight.dns_context.ip_only",
        "IP-only metadata"
      )
    case .unknown:
      return L10n.string(
        "rule_insight.dns_context.unknown",
        "Not reported"
      )
    }
  }

  private var icon: String {
    switch explanation.outcome {
    case .ruleHit:
      return "checkmark.seal.fill"
    case .direct:
      return "arrow.forward.circle"
    case .unknown:
      return "questionmark.circle"
    }
  }

  private var tint: Color {
    switch explanation.outcome {
    case .ruleHit:
      return AppPalette.success
    case .direct:
      return AppPalette.warning
    case .unknown:
      return AppPalette.accent
    }
  }

  private var dnsTint: Color {
    switch explanation.dnsContext {
    case .fakeIPMapped:
      return AppPalette.success
    case .sniffedDomain, .metadataDomain:
      return AppPalette.accent
    case .ipOnly:
      return AppPalette.warning
    case .unknown:
      return AppPalette.inkMuted
    }
  }
}

private struct RouteFactPill: View {
  let title: String
  let value: String
  let tint: Color

  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title)
        .appFont(size: 11, weight: .regular)
        .tracking(-0.08)
        .foregroundStyle(.secondary)
      Text(DisplayValue.fallback(value))
        .appFont(size: 13, weight: .semibold)
        .tracking(-0.12)
        .foregroundStyle(AppPalette.ink)
        .lineLimit(2)
        .minimumScaleFactor(0.78)
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 8)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
  }
}

private struct RuleInsightDetailRow: View {
  let title: String
  let value: String

  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title)
        .appFont(size: 12, weight: .regular)
        .tracking(-0.12)
        .foregroundStyle(.secondary)
      Text(DisplayValue.fallback(value))
        .appFont(size: 13, weight: .semibold)
        .tracking(-0.12)
        .foregroundStyle(AppPalette.ink)
        .fixedSize(horizontal: false, vertical: true)
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct LogsPage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: LogsPresentationModel

  init(viewModel: ConsoleViewModel) {
    self.viewModel = viewModel
    presentation = viewModel.logsPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("logs.title", "Logs"),
        subtitle: L10n.string("logs.subtitle", "A focused stream of the latest runtime events."),
        trailing: AnyView(
          HStack(spacing: 12) {
            Button {
              viewModel.copyLogs()
            } label: {
              Label(
                L10n.string("action.copy", "Copy"),
                systemImage: "doc.on.doc"
              )
              .labelStyle(.titleAndIcon)
              .font(.footnote.weight(.semibold))
            }
            .buttonStyle(AppleSecondaryButtonStyle())
            .disabled(presentation.state.isEmpty)

            Button {
              viewModel.clearLogs()
            } label: {
              Label(
                L10n.string("action.clear", "Clear"),
                systemImage: "trash"
              )
              .labelStyle(.titleAndIcon)
              .font(.footnote.weight(.semibold))
            }
            .buttonStyle(AppleSecondaryButtonStyle())
            .disabled(presentation.state.isEmpty)
          }
        )
      ) {
        if presentation.state.isEmpty {
          EmptyStateCard(
            icon: "list.bullet.rectangle.portrait",
            title: L10n.string("logs.empty_title", "No logs yet"),
            message: L10n.string("logs.empty_message", "Runtime logs will appear once the embedded core emits events.")
          )
        } else {
          AppGroupedList {
            let logs = presentation.state.records
            let lastLogID = logs.last?.id
            ForEach(logs) { log in
              LogListRow(
                timestamp: log.timestamp,
                level: log.level,
                message: log.message
              )
              if log.id != lastLogID {
                AppListDivider(leadingInset: 58)
              }
            }
          }
          if presentation.state.hiddenCount > 0 {
            Text(L10n.format("logs.preview_limit", "Showing the latest %d log lines.", presentation.state.records.count))
              .font(.footnote)
              .foregroundStyle(.secondary)
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.logs", "Logs"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

private struct LogListRow: View {
  let timestamp: String
  let level: String
  let message: String

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Circle()
        .fill(levelTint)
        .frame(width: 10, height: 10)
        .padding(.top, 5)
        .frame(width: 34)

      VStack(alignment: .leading, spacing: 4) {
        HStack(spacing: 6) {
          Text(timestamp)
            .appFont(size: 12, weight: .regular, design: .monospaced)
            .foregroundStyle(.secondary)
          Text(level.uppercased())
            .appFont(size: 11, weight: .semibold, design: .monospaced)
            .foregroundStyle(levelTint)
        }
        Text(message)
          .appFont(size: 12, weight: .regular, design: .monospaced)
          .foregroundStyle(AppPalette.ink)
          .fixedSize(horizontal: false, vertical: true)
      }
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .contentShape(Rectangle())
  }

  private var levelTint: Color {
    switch level.lowercased() {
    case "error", "fatal":
      return AppPalette.danger
    case "warn", "warning":
      return AppPalette.warning
    case "info":
      return AppPalette.accent
    default:
      return AppPalette.inkMuted
    }
  }
}

struct ResourcesPage: View {
  @ObservedObject private var presentation: ResourcesPresentationModel

  init(viewModel: ConsoleViewModel) {
    presentation = viewModel.resourcesPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("resources.title", "Remote Resources"),
        subtitle: L10n.string("resources.subtitle", "Providers, remote URLs, paths, and refresh intervals discovered in the current bundle.")
      ) {
        if presentation.state.isEmpty {
          EmptyStateCard(
            icon: "shippingbox",
            title: L10n.string("resources.empty_title", "No remote resources"),
            message: L10n.string("resources.empty_message", "No providers or remote URLs were discovered in the current bundle.")
          )
        } else {
          AppGroupedList {
            let resources = presentation.state.resources
            let lastResourceID = resources.last?.id
            ForEach(resources) { resource in
              ResourceListRow(resource: resource)
              if resource.id != lastResourceID {
                AppListDivider(leadingInset: 58)
              }
            }
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.resources", "Resources"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

struct CorePage: View {
  @ObservedObject private var viewModel: ConsoleViewModel
  @ObservedObject private var presentation: CorePresentationModel

  init(viewModel: ConsoleViewModel) {
    self.viewModel = viewModel
    presentation = viewModel.corePresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("core.mihomo.title", "Mihomo Summary"),
        subtitle: L10n.string("core.mihomo.subtitle", "Current routing mode and logging settings.")
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ValueRow(title: L10n.string("runtime.summary.mode", "Mode"), value: DisplayValue.mode(presentation.state.mihomoSummary.mode))
          ValueRow(title: L10n.string("core.mihomo.log_level", "Log Level"), value: DisplayValue.fallback(presentation.state.mihomoSummary.logLevel))
        }
      }

      AppSurface(
        title: L10n.string("core.tun.title", "TUN Summary"),
        subtitle: L10n.string("core.tun.subtitle", "The packet tunnel stack and hijack settings currently persisted for runtime startup.")
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ValueRow(title: L10n.string("core.tun.enabled", "Enabled"), value: DisplayValue.bool(presentation.state.tunSummary.enabled))
          ValueRow(title: L10n.string("core.tun.stack", "Stack"), value: presentation.state.tunSummary.effectiveStack)
          ValueRow(title: L10n.string("core.tun.mtu", "MTU"), value: String(presentation.state.tunSummary.effectiveMTU))
          WrappedValueGroup(title: L10n.string("core.tun.dns_hijack", "DNS Hijack"), values: presentation.state.tunSummary.dnsHijack)
          if let path = viewModel.extensionSnapshot.networkPath {
            ValueRow(title: L10n.string("core.network.path", "Network"), value: path.status == "satisfied"
              ? path.interfaces.joined(separator: " / ") : L10n.string("core.network.waiting", "Waiting for Network"))
          }
          if let statistics = viewModel.extensionSnapshot.packetFlowStatistics {
            ValueRow(title: L10n.string("core.queue.current", "Packet Buffer"), value: ByteCountFormatter.string(fromByteCount: Int64(statistics["bytes"] ?? 0), countStyle: .memory))
            ValueRow(title: L10n.string("core.queue.peak", "Peak Buffer"), value: ByteCountFormatter.string(fromByteCount: Int64(statistics["peakBytes"] ?? 0), countStyle: .memory))
            ValueRow(title: L10n.string("core.queue.dropped", "Dropped Packets"), value: String((statistics["droppedPackets"] ?? 0) &+ (statistics["oversizedPackets"] ?? 0)))
          }
        }
      }
    }
    .navigationTitle(L10n.string("page.core", "Core"))
    .navigationBarTitleDisplayMode(.inline)
  }
}

struct OverridePage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: OverridePresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void

  init(viewModel: ConsoleViewModel, onImportRequested: @escaping (ImportedConfigKind) -> Void) {
    self.viewModel = viewModel
    self.onImportRequested = onImportRequested
    presentation = viewModel.overridePresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("override.title", "Override"),
        subtitle: L10n.string(
          "override.subtitle",
          "Apply YAML overrides to routing, DNS and resource providers."
        )
      ) {
        VStack(alignment: .leading, spacing: 12) {
          ValueRow(title: L10n.string("override.yaml_bytes", "YAML Bytes"), value: "\(presentation.state.overrideYaml.utf8.count)")
          Button(L10n.string("override.import_yaml", "Import Override YAML")) { onImportRequested(.overrideYAML) }
            .buttonStyle(AppleUtilityButtonStyle())
        }
      }

      EditorSurface(
        title: L10n.string("override.editor.yaml_title", "Override YAML"),
        prompt: L10n.string("override.editor.yaml_prompt", "YAML definitions for routing, DNS and resources."),
        text: overrideYamlBinding,
        minHeight: 220
      )

    }
    .navigationTitle(L10n.string("page.override", "Override"))
    .navigationBarTitleDisplayMode(.inline)
  }

  private var overrideYamlBinding: Binding<String> {
    Binding(
      get: { presentation.state.overrideYaml },
      set: { viewModel.overrideYaml = $0 }
    )
  }

}


struct SettingsPage: View {
  let viewModel: ConsoleViewModel
  @ObservedObject private var presentation: SettingsPresentationModel
  let onImportRequested: (ImportedConfigKind) -> Void

  init(viewModel: ConsoleViewModel, onImportRequested: @escaping (ImportedConfigKind) -> Void) {
    self.viewModel = viewModel
    self.onImportRequested = onImportRequested
    presentation = viewModel.settingsPresentation
  }

  var body: some View {
    AppPageContainer {
      AppSurface(
        title: L10n.string("settings.compatibility.title", "App Settings"),
        subtitle: L10n.string(
          "settings.compatibility.subtitle",
          "Import routing preferences and delay-test settings."
        )
      ) {
        VStack(alignment: .leading, spacing: 12) {
          Button(L10n.string("settings.import_app_config", "Import App Config JSON")) {
            onImportRequested(.appConfigJSON)
          }
          .buttonStyle(AppleUtilityButtonStyle())

        }
      }

      AppSurface(
        title: L10n.string("settings.export.title", "Export Bundle"),
        subtitle: L10n.string("settings.export.subtitle", "Persist the current bundle into the shared export directory.")
      ) {
        VStack(alignment: .leading, spacing: 12) {
          TextField(L10n.string("settings.export.field_name", "Export file name"), text: exportBundleNameBinding)
            .appleTextField()
          HStack(spacing: 10) {
            Button(L10n.string("settings.export.now", "Export Now")) { viewModel.exportCurrentBundle() }
              .buttonStyle(ApplePrimaryButtonStyle())
            if let path = presentation.state.lastExportPath {
              Text(path)
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(3)
            }
          }
        }
      }

      EditorSurface(
        title: L10n.string("settings.app_config.title", "App Config JSON"),
        prompt: L10n.string("settings.app_config.prompt", "Routing preferences and delay-test settings."),
        text: appConfigBinding,
        minHeight: 240
      )
    }
    .navigationTitle(L10n.string("page.settings", "Settings"))
    .navigationBarTitleDisplayMode(.inline)
  }

  private var exportBundleNameBinding: Binding<String> {
    Binding(
      get: { presentation.state.exportBundleName },
      set: { viewModel.exportBundleName = $0 }
    )
  }

  private var appConfigBinding: Binding<String> {
    Binding(
      get: { presentation.state.appConfigJson },
      set: { viewModel.appConfigJson = $0 }
    )
  }
}
