import Foundation

final class ConsoleProfileLibraryCoordinator: @unchecked Sendable {
  private let queue = DispatchQueue(
    label: "org.mihomo.party.ios.console.profile-library",
    qos: .utility
  )

  func loadLibrarySnapshot() async -> (profiles: [ProfileBundleRecord], backups: [BackupRecord]) {
    await withCheckedContinuation { continuation in
      queue.async {
        continuation.resume(
          returning: (
            profiles: SharedStore.readProfileLibrary(),
            backups: SharedStore.readBackups()
          )
        )
      }
    }
  }

  func findProfile(matching input: CompatibilityInput) async -> ProfileBundleRecord? {
    await withCheckedContinuation { continuation in
      queue.async {
        continuation.resume(
          returning: SharedStore.readProfileLibrary().first(where: { $0.input == input })
        )
      }
    }
  }

  func saveProfile(_ record: ProfileBundleRecord) async throws {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          try SharedStore.saveProfileRecord(record)
          continuation.resume(returning: ())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func upsertImportedProfile(
    input: CompatibilityInput,
    fallbackName: String?,
    now: Date = .now
  ) async throws -> ProfileBundleRecord {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          let records = SharedStore.readProfileLibrary()
          let existingRecord = records.first { $0.input == input }
          let trimmedFallbackName = fallbackName?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
          let resolvedName = existingRecord?.name
            ?? (
              trimmedFallbackName.isEmpty
                ? L10n.format("profiles.generated_name", "Profile %d", records.count + 1)
                : trimmedFallbackName
            )
          let record = ProfileBundleRecord(
            id: existingRecord?.id ?? UUID().uuidString,
            name: resolvedName,
            input: input,
            remoteSource: existingRecord?.remoteSource,
            createdAt: existingRecord?.createdAt ?? now,
            updatedAt: now
          )
          try SharedStore.saveProfileRecord(record)
          continuation.resume(returning: record)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func deleteProfile(id: String) async throws {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          try SharedStore.deleteProfileRecord(id: id)
          continuation.resume(returning: ())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func createBackup(
    name: String,
    input: CompatibilityInput,
    runtimeStatus: RuntimeStatus
  ) async throws -> BackupRecord {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          let record = try SharedStore.createBackupRecord(
            name: name,
            input: input,
            runtimeStatus: runtimeStatus
          )
          continuation.resume(returning: record)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func deleteBackup(id: String) async throws {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          try SharedStore.deleteBackup(id: id)
          continuation.resume(returning: ())
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func exportCurrentBundle(
    name: String,
    input: CompatibilityInput,
    runtimeStatus: RuntimeStatus,
    validationReport: CompatibilityValidationReport
  ) async throws -> URL {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          let url = try SharedStore.exportCurrentBundle(
            name: name,
            input: input,
            runtimeStatus: runtimeStatus,
            validationReport: validationReport
          )
          continuation.resume(returning: url)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func upsertRemoteImportedProfile(
    remoteSource: String,
    input: CompatibilityInput,
    fallbackName: String?,
    now: Date = .now
  ) async throws -> ProfileBundleRecord {
    try await withCheckedThrowingContinuation { continuation in
      queue.async {
        do {
          let record = ProfileBundleRecord.recordForRemoteImport(
            remoteSource: remoteSource,
            input: input,
            existingRecords: SharedStore.readProfileLibrary(),
            fallbackName: fallbackName,
            now: now
          )
          try SharedStore.saveProfileRecord(record)
          continuation.resume(returning: record)
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }
}
