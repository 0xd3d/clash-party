import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
  @State private var shouldLoadConsole = false

  var body: some View {
    Group {
      if shouldLoadConsole {
        ConsoleRootView()
          .transition(.opacity)
      } else {
        AppLaunchSplashView()
          .transition(.opacity)
      }
    }
    .animation(.easeOut(duration: 0.18), value: shouldLoadConsole)
    .task {
      guard !shouldLoadConsole else { return }
      await Task.yield()
      try? await Task.sleep(nanoseconds: 180_000_000)
      shouldLoadConsole = true
    }
  }
}

private struct ConsoleRootView: View {
  @Environment(\.scenePhase) private var scenePhase
  @StateObject private var viewModel = ConsoleViewModel()
  @State private var showingImporter = false
  @State private var importKind: ImportedConfigKind = .profileYAML

  var body: some View {
    AppShellView(
      viewModel: viewModel,
      shellPresentation: viewModel.shellPresentation,
      onImportRequested: { kind in
        importKind = kind
        showingImporter = true
      }
    )
    .task {
      #if DEBUG
      let arguments = CommandLine.arguments
      if let index = arguments.firstIndex(of: "--codex-validation-profile"), index + 1 < arguments.count {
        guard await viewModel.prepareDebugValidationProfile(fileName: arguments[index + 1]) else { return }
        if arguments.contains("--codex-auto-start-tunnel") {
          viewModel.startTunnel()
        }
        return
      }
      #endif
      viewModel.bootstrap()
      if CommandLine.arguments.contains("--codex-auto-start-tunnel") {
        try? await Task.sleep(for: .seconds(2))
        viewModel.startTunnel()
      }
    }
    .onChange(of: scenePhase, initial: true) { _, phase in
      viewModel.handleScenePhase(phase)
    }
    .fileImporter(
      isPresented: $showingImporter,
      allowedContentTypes: [.plainText, .json]
    ) { result in
      if case .success(let url) = result {
        viewModel.importTextFile(from: url, kind: importKind)
      }
    }
  }
}

private struct AppLaunchSplashView: View {
  var body: some View {
    ZStack {
      AppPalette.parchment
        .ignoresSafeArea()

      VStack(spacing: 18) {
        ZStack {
          RoundedRectangle(cornerRadius: 28, style: .continuous)
            .fill(AppPalette.pearl)
            .frame(width: 88, height: 88)
            .shadow(color: .black.opacity(0.08), radius: 18, x: 0, y: 10)

          Image(systemName: "point.3.connected.trianglepath.dotted")
            .font(.system(size: 34, weight: .semibold))
            .foregroundStyle(AppPalette.accent)
        }

        VStack(spacing: 8) {
          Text("Clash Party")
            .font(.system(.largeTitle, design: .rounded, weight: .bold))
            .foregroundStyle(AppPalette.ink)

          Text(L10n.string("launch.subtitle", "Preparing routing engine"))
            .font(.callout.weight(.medium))
            .foregroundStyle(AppPalette.inkMuted)
        }

        ProgressView()
          .controlSize(.small)
          .tint(AppPalette.accent)
          .padding(.top, 4)
      }
      .padding(.horizontal, 28)
      .accessibilityElement(children: .combine)
      .accessibilityLabel(
        Text(L10n.string("launch.accessibility.loading", "Clash Party is preparing the routing engine"))
      )
    }
  }
}
