import Foundation

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
  guard condition() else {
    fputs("FAIL: \(message)\n", stderr)
    exit(1)
  }
}

@main
struct IPhoneAppleLayoutRegressionCheck {
  static func main() {
    let scriptURL = URL(fileURLWithPath: #filePath)
    let projectRootURL = scriptURL.deletingLastPathComponent().deletingLastPathComponent()
    let designURL = projectRootURL.appendingPathComponent("DESIGN.md")
    let designSystemURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppDesignSystem.swift")
    let appPagesURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppPages.swift")
    let appShellURL = projectRootURL.appendingPathComponent("ClashParty/Views/AppShellView.swift")

    let designSource = (try? String(contentsOf: designURL, encoding: .utf8)) ?? ""
    let designSystemSource = (try? String(contentsOf: designSystemURL, encoding: .utf8)) ?? ""
    let appPagesSource = (try? String(contentsOf: appPagesURL, encoding: .utf8)) ?? ""
    let appShellSource = (try? String(contentsOf: appShellURL, encoding: .utf8)) ?? ""

    expect(!designSource.isEmpty, "getdesign Apple DESIGN.md should exist")
    expect(designSource.contains("name: Apple"), "DESIGN.md should be the Apple design reference")
    expect(designSource.contains("#0066cc"), "Apple design reference should expose Action Blue")

    expect(
      designSystemSource.contains("struct PhoneStatusHero: View"),
      "design system should define the iPhone connection hero"
    )
    expect(
      designSystemSource.contains("struct PhoneQuickAction: View"),
      "design system should define thumb-friendly quick actions"
    )
    expect(
      designSystemSource.contains("struct PhoneStatChip: View"),
      "design system should define compact phone stat chips"
    )
    expect(
      designSystemSource.contains("struct NodeGroupCard: View"),
      "design system should define mobile node group cards"
    )

    expect(appPagesSource.contains("PhoneStatusHero("), "Home should use the iPhone status hero")
    expect(appPagesSource.contains("heroStatusSubtitle"), "Home hero should summarize current node and mode")
    expect(appPagesSource.contains("PhoneQuickAction("), "Home should use phone quick actions")
    expect(appPagesSource.contains("PhoneStatChip("), "Home should use phone stat chips")
    expect(appPagesSource.contains("NodeGroupCard("), "Nodes should use mobile group cards")
    expect(
      appPagesSource.contains("LazyVGrid(columns: primaryActionColumns"),
      "Home quick actions should remain a compact iPhone grid"
    )

    expect(appShellSource.contains("TabView(selection: $selectedTab)"), "iPhone shell should keep native bottom tabs")
    expect(appShellSource.contains("case nodes"), "iPhone shell should preserve Nodes as a primary tab")

    print("PASS: iPhone Apple layout regression checks passed")
  }
}
