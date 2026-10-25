#import "MihomoPacketFlowBridge.h"

#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "MihomoPacketQueueBudget.h"

#if __has_include("ClashParty-Swift.h")
#import "ClashParty-Swift.h"
#define MIHOMO_HAS_SHAREDSTORE_OBJC_BRIDGE 1
#elif __has_include("ClashPartyTunnel-Swift.h")
#import "ClashPartyTunnel-Swift.h"
#define MIHOMO_HAS_SHAREDSTORE_OBJC_BRIDGE 1
#else
#define MIHOMO_HAS_SHAREDSTORE_OBJC_BRIDGE 0
#endif

static const void *MihomoPacketFlowQueueSpecificKey = &MihomoPacketFlowQueueSpecificKey;

static void MihomoNativeAppendSharedLogSync(NSString *level, NSString *message);
static void MihomoNativeAppendSharedLog(NSString *level, NSString *message);
static BOOL MihomoPacketFlowDiagnosticsEnabled(void);
static void MihomoNativeAppendDiagnosticSharedLog(NSString *level, NSString *message);

static void MihomoNativeAppendSharedLogSync(NSString *level, NSString *message) {
#if MIHOMO_HAS_SHAREDSTORE_OBJC_BRIDGE
  [SharedStoreObjCBridge appendSharedLogLevel:(level ?: @"debug") message:(message ?: @"")];
#else
  (void)level;
  (void)message;
#endif
}

static void MihomoNativeAppendCriticalSharedLog(NSString *level, NSString *message) {
  MihomoNativeAppendSharedLogSync(level ?: @"debug", message ?: @"");
}

static void MihomoNativeAppendSharedLog(NSString *level, NSString *message) {
#if MIHOMO_HAS_SHAREDSTORE_OBJC_BRIDGE
  [SharedStoreObjCBridge appendSharedLogNonBlockingLevel:([level copy] ?: @"debug")
                                                 message:([message copy] ?: @"")];
#else
  (void)level;
  (void)message;
#endif
}

static BOOL MihomoPacketFlowDiagnosticsEnabled(void) {
  static BOOL enabled = NO;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    const char *value = getenv("MIHOMO_IOS_PACKET_FLOW_DEBUG");
    enabled = value != NULL
      && (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0);
  });
  return enabled;
}

static void MihomoNativeAppendDiagnosticSharedLog(NSString *level, NSString *message) {
  if (!MihomoPacketFlowDiagnosticsEnabled()) {
    return;
  }
  MihomoNativeAppendSharedLog(level, message);
}

void MihomoIOSNativeLog(const char *level, const char *message) {
  @autoreleasepool {
    NSString *objcLevel = level != NULL ? [NSString stringWithUTF8String:level] : @"debug";
    NSString *objcMessage = message != NULL ? [NSString stringWithUTF8String:message] : @"";
    MihomoNativeAppendSharedLog(objcLevel, objcMessage);
  }
}

static __strong NEPacketTunnelFlow *MihomoAttachedFlow = nil;
static BOOL MihomoPacketFlowActive = NO;
static BOOL MihomoPacketFlowReadPending = NO;
static BOOL MihomoPacketFlowReadingArmed = NO;
static BOOL MihomoPacketFlowObservedRead = NO;
static BOOL MihomoPacketFlowObservedSuccessfulWrite = NO;
static BOOL MihomoPacketFlowLoggedFirstReadSummary = NO;
static BOOL MihomoPacketFlowLoggedFirstWriteSummary = NO;
static BOOL MihomoPacketFlowLoggedFirstNonDNSReadSummary = NO;
static BOOL MihomoPacketFlowLoggedFirstNonDNSWriteSummary = NO;
static NSMutableSet<NSString *> *MihomoPacketFlowLoggedReadFlowSummaries = nil;
static NSMutableSet<NSString *> *MihomoPacketFlowLoggedWriteFlowSummaries = nil;
static NSUInteger MihomoPacketFlowLoggedReadFlowSummaryCount = 0;
static NSUInteger MihomoPacketFlowLoggedWriteFlowSummaryCount = 0;
static const NSUInteger MihomoPacketFlowMaxLoggedUniqueNonDNSFlowsPerDirection = 12;

typedef struct MihomoPacketNode {
  NSUInteger length;
  void *bytes;
  struct MihomoPacketNode *next;
} MihomoPacketNode;

static MihomoPacketNode *MihomoPacketQueueHead = NULL;
static MihomoPacketNode *MihomoPacketQueueTail = NULL;
static NSUInteger MihomoPacketQueueCount = 0;
static BOOL MihomoPacketQueueInitialized = NO;
static MihomoPacketQueueBudget MihomoPacketBudget = {0};
static BOOL MihomoPacketFlowReadPaused = NO;
static BOOL MihomoPacketFlowDropIPv6 = NO;
static BOOL MihomoPacketFlowBlocked = NO;
static uint64_t MihomoPacketFlowBlockedPackets = 0;
static uint64_t MihomoPacketFlowDroppedIPv6 = 0;
static uint64_t MihomoPacketFlowGeneration = 0;
static uint64_t MihomoPacketReaderGeneration = 0;

static dispatch_queue_t MihomoPacketFlowQueue(void);
static dispatch_semaphore_t MihomoPacketFlowSemaphore(void);
static void MihomoPacketFlowPerformLocked(dispatch_block_t block);
static void MihomoPacketQueueEnsureInitializedLocked(void);
static void MihomoPacketQueueClearLocked(void);
static BOOL MihomoPacketQueueAppendDataLocked(NSData *packet);
static MihomoPacketNode *MihomoPacketQueuePopLocked(void);
static void MihomoPacketFlowScheduleReadLocked(void);
static void MihomoPacketFlowAttachWithPolicy(NEPacketTunnelFlow *flow, BOOL dropIPv6);
static void MihomoPacketFlowAttach(NEPacketTunnelFlow *flow);
static void MihomoPacketFlowClear(void);
static BOOL MihomoPacketFlowIsAttached(void);
static NSString *MihomoPacketFlowPacketSummary(const void *buffer, int length, BOOL *isDNS);
static void MihomoPacketFlowMaybeLogUniqueNonDNSFlow(BOOL fromIOS, NSString *summary);
static int MihomoPacketFlowReadIntoBuffer(void *buffer, int maxLength);
static int MihomoPacketFlowWriteFromBuffer(const void *buffer, int length);
static NSString *MihomoPacketFlowObjectClassName(id object);

static dispatch_queue_t MihomoPacketFlowQueue(void) {
  static dispatch_queue_t queue;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    queue = dispatch_queue_create("org.mihomo.party.ios.packet-flow", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(queue, MihomoPacketFlowQueueSpecificKey, (void *)MihomoPacketFlowQueueSpecificKey, NULL);
  });
  return queue;
}

static dispatch_semaphore_t MihomoPacketFlowSemaphore(void) {
  static dispatch_semaphore_t semaphore;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    semaphore = dispatch_semaphore_create(0);
  });
  return semaphore;
}

static NSString *MihomoPacketFlowObjectClassName(id object) {
  return object != nil ? NSStringFromClass([object class]) : @"nil";
}

static void MihomoPacketFlowPerformLocked(dispatch_block_t block) {
  if (dispatch_get_specific(MihomoPacketFlowQueueSpecificKey) != NULL) {
    block();
    return;
  }

  dispatch_sync(MihomoPacketFlowQueue(), block);
}

static void MihomoPacketQueueEnsureInitializedLocked(void) {
  if (!MihomoPacketQueueInitialized) {
    MihomoPacketQueueInitialized = YES;
    MihomoNativeAppendSharedLog(
      @"debug",
      @"Packet flow bridge initialized the shared packet buffer."
    );
  }
}

static void MihomoPacketQueueClearLocked(void) {
  MihomoPacketNode *node = MihomoPacketQueueHead;
  while (node != NULL) {
    MihomoPacketNode *next = node->next;
    if (node->bytes != NULL) {
      free(node->bytes);
    }
    free(node);
    node = next;
  }

  MihomoPacketQueueHead = NULL;
  MihomoPacketQueueTail = NULL;
  MihomoPacketQueueCount = 0;
  MihomoPacketBudget.count = 0;
  MihomoPacketBudget.bytes = 0;
  MihomoPacketFlowReadPaused = NO;
  MihomoPacketQueueInitialized = NO;
}

static BOOL MihomoPacketQueueAppendDataLocked(NSData *packet) {
  if (packet == nil || packet.length == 0) {
    return NO;
  }

  MihomoPacketQueueEnsureInitializedLocked();
  if (!MihomoQueueCanAppend(&MihomoPacketBudget, packet.length)) {
    MihomoPacketBudget.droppedPackets++;
    return NO;
  }

  MihomoPacketNode *node = calloc(1, sizeof(MihomoPacketNode));
  if (node == NULL) {
    MihomoNativeAppendCriticalSharedLog(@"error", @"Packet flow bridge failed to allocate a queue node.");
    return NO;
  }

  void *bytes = malloc(packet.length);
  if (bytes == NULL) {
    free(node);
    MihomoNativeAppendCriticalSharedLog(@"error", @"Packet flow bridge failed to allocate packet bytes.");
    return NO;
  }

  [packet getBytes:bytes length:packet.length];
  node->length = packet.length;
  node->bytes = bytes;
  node->next = NULL;

  if (MihomoPacketQueueTail != NULL) {
    MihomoPacketQueueTail->next = node;
  } else {
    MihomoPacketQueueHead = node;
  }
  MihomoPacketQueueTail = node;
  MihomoPacketQueueCount += 1;
  MihomoQueueDidAppend(&MihomoPacketBudget, packet.length);
  return YES;
}

static MihomoPacketNode *MihomoPacketQueuePopLocked(void) {
  MihomoPacketNode *node = MihomoPacketQueueHead;
  if (node == NULL) {
    return NULL;
  }

  MihomoPacketQueueHead = node->next;
  if (MihomoPacketQueueHead == NULL) {
    MihomoPacketQueueTail = NULL;
  }
  node->next = NULL;
  MihomoQueueDidPop(&MihomoPacketBudget, node->length);
  if (MihomoPacketQueueCount > 0) {
    MihomoPacketQueueCount -= 1;
  }
  return node;
}

static void MihomoPacketFlowScheduleReadLocked(void) {
  if (MihomoPacketFlowReadPending || !MihomoPacketFlowActive || MihomoAttachedFlow == nil) {
    return;
  }

  if (MihomoPacketFlowReadPaused && !MihomoQueueCanResume(&MihomoPacketBudget)) { return; }
  if (MihomoQueueShouldPause(&MihomoPacketBudget)) {
    MihomoPacketFlowReadPaused = YES;
    return;
  }
  MihomoPacketFlowReadPaused = NO;
  MihomoPacketFlowReadPending = YES;
  uint64_t generation = MihomoPacketFlowGeneration;
  NEPacketTunnelFlow *flow = MihomoAttachedFlow;
  [flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
    dispatch_async(MihomoPacketFlowQueue(), ^{
      if (generation != MihomoPacketFlowGeneration) { return; }
      MihomoPacketFlowReadPending = NO;
      if (!MihomoPacketFlowActive || MihomoAttachedFlow == nil || MihomoAttachedFlow != flow) {
        return;
      }

      MihomoPacketQueueEnsureInitializedLocked();
      BOOL enqueuedAnyPacket = NO;
      for (id candidate in packets) {
        if (![candidate isKindOfClass:[NSData class]]) {
          MihomoNativeAppendCriticalSharedLog(
            @"error",
            [NSString stringWithFormat:
              @"Packet flow bridge received a packet object with unexpected class %@. Dropping it before enqueue.",
              MihomoPacketFlowObjectClassName(candidate)]
          );
          continue;
        }

        NSData *packet = (NSData *)candidate;
        if (MihomoPacketFlowBlocked) { MihomoPacketFlowBlockedPackets++; continue; }
        if (MihomoPacketFlowDropIPv6 && packet.length > 0 && (((const uint8_t *)packet.bytes)[0] >> 4) == 6) {
          MihomoPacketFlowDroppedIPv6++;
          continue;
        }
        if (MihomoPacketQueueAppendDataLocked(packet)) {
          enqueuedAnyPacket = YES;
        }
      }

      if (enqueuedAnyPacket) {
        dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
      }

      MihomoPacketFlowScheduleReadLocked();
    });
  }];
}

static void MihomoPacketFlowAttach(NEPacketTunnelFlow *flow) {
  MihomoPacketFlowAttachWithPolicy(flow, NO);
}

static void MihomoPacketFlowAttachWithPolicy(NEPacketTunnelFlow *flow, BOOL dropIPv6) {
  MihomoPacketFlowPerformLocked(^{
    MihomoPacketFlowGeneration++;
    MihomoPacketReaderGeneration++;
    uint64_t generation = MihomoPacketFlowGeneration;
    MihomoAttachedFlow = flow;
    MihomoPacketFlowActive = (flow != nil);
    MihomoPacketFlowDropIPv6 = dropIPv6;
    MihomoPacketFlowBlocked = NO;
    MihomoPacketFlowBlockedPackets = 0;
    MihomoPacketFlowDroppedIPv6 = 0;
    MihomoPacketFlowReadPending = NO;
    MihomoPacketFlowReadingArmed = NO;
    MihomoPacketFlowObservedRead = NO;
    MihomoPacketFlowObservedSuccessfulWrite = NO;
    MihomoPacketFlowLoggedFirstReadSummary = NO;
    MihomoPacketFlowLoggedFirstWriteSummary = NO;
    MihomoPacketFlowLoggedFirstNonDNSReadSummary = NO;
    MihomoPacketFlowLoggedFirstNonDNSWriteSummary = NO;
    MihomoPacketFlowLoggedReadFlowSummaries = nil;
    MihomoPacketFlowLoggedWriteFlowSummaries = nil;
    MihomoPacketFlowLoggedReadFlowSummaryCount = 0;
    MihomoPacketFlowLoggedWriteFlowSummaryCount = 0;
    MihomoPacketQueueClearLocked();
    memset(&MihomoPacketBudget, 0, sizeof(MihomoPacketBudget));
    MihomoPacketQueueEnsureInitializedLocked();

    MihomoNativeAppendSharedLog(
      @"debug",
      MihomoPacketFlowActive
        ? @"Packet flow bridge stored the packet flow state."
        : @"Packet flow bridge received a nil flow while attaching."
    );

    if (!MihomoPacketFlowActive) {
      return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), MihomoPacketFlowQueue(), ^{
      if (generation != MihomoPacketFlowGeneration || !MihomoPacketFlowActive || MihomoAttachedFlow == nil || MihomoAttachedFlow != flow) {
        return;
      }

      MihomoPacketFlowReadingArmed = YES;
      MihomoNativeAppendSharedLog(@"debug", @"Packet flow bridge armed the first read cycle after the startup grace period.");
      MihomoPacketFlowScheduleReadLocked();
    });
  });
}

static void MihomoPacketFlowClear(void) {
  MihomoPacketFlowPerformLocked(^{
    MihomoPacketFlowGeneration++;
    MihomoPacketReaderGeneration++;
    MihomoPacketFlowActive = NO;
    MihomoPacketFlowDropIPv6 = NO;
    MihomoPacketFlowBlocked = NO;
    MihomoAttachedFlow = nil;
    MihomoPacketFlowReadPending = NO;
    MihomoPacketFlowReadingArmed = NO;
    MihomoPacketFlowObservedRead = NO;
    MihomoPacketFlowObservedSuccessfulWrite = NO;
    MihomoPacketFlowLoggedFirstReadSummary = NO;
    MihomoPacketFlowLoggedFirstWriteSummary = NO;
    MihomoPacketFlowLoggedFirstNonDNSReadSummary = NO;
    MihomoPacketFlowLoggedFirstNonDNSWriteSummary = NO;
    MihomoPacketFlowLoggedReadFlowSummaries = nil;
    MihomoPacketFlowLoggedWriteFlowSummaries = nil;
    MihomoPacketFlowLoggedReadFlowSummaryCount = 0;
    MihomoPacketFlowLoggedWriteFlowSummaryCount = 0;
    MihomoPacketQueueClearLocked();
    dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
  });
}

static BOOL MihomoPacketFlowIsAttached(void) {
  __block BOOL attached = NO;
  MihomoPacketFlowPerformLocked(^{
    attached = MihomoPacketFlowActive && MihomoAttachedFlow != nil;
  });
  return attached;
}

static BOOL MihomoPacketFlowHasObservedRead(void) {
  __block BOOL observed = NO;
  MihomoPacketFlowPerformLocked(^{
    observed = MihomoPacketFlowObservedRead;
  });
  return observed;
}

static BOOL MihomoPacketFlowHasObservedSuccessfulWrite(void) {
  __block BOOL observed = NO;
  MihomoPacketFlowPerformLocked(^{
    observed = MihomoPacketFlowObservedSuccessfulWrite;
  });
  return observed;
}

static NSString *MihomoPacketFlowIPv4AddressString(const uint8_t *bytes) {
  char buffer[INET_ADDRSTRLEN] = {0};
  if (inet_ntop(AF_INET, bytes, buffer, sizeof(buffer)) == NULL) {
    return @"0.0.0.0";
  }
  return [NSString stringWithUTF8String:buffer];
}

static NSString *MihomoPacketFlowIPv6AddressString(const uint8_t *bytes) {
  char buffer[INET6_ADDRSTRLEN] = {0};
  if (inet_ntop(AF_INET6, bytes, buffer, sizeof(buffer)) == NULL) {
    return @"::";
  }
  return [NSString stringWithUTF8String:buffer];
}

static NSString *MihomoPacketFlowTCPFlagsString(uint8_t flags) {
  NSMutableArray<NSString *> *parts = [NSMutableArray array];
  if ((flags & 0x02) != 0) {
    [parts addObject:@"SYN"];
  }
  if ((flags & 0x10) != 0) {
    [parts addObject:@"ACK"];
  }
  if ((flags & 0x01) != 0) {
    [parts addObject:@"FIN"];
  }
  if ((flags & 0x04) != 0) {
    [parts addObject:@"RST"];
  }
  if ((flags & 0x08) != 0) {
    [parts addObject:@"PSH"];
  }
  if ((flags & 0x20) != 0) {
    [parts addObject:@"URG"];
  }
  return parts.count > 0 ? [parts componentsJoinedByString:@"|"] : @"none";
}

static NSString *MihomoPacketFlowPacketSummary(const void *buffer, int length, BOOL *isDNS) {
  if (isDNS != NULL) {
    *isDNS = NO;
  }
  if (buffer == NULL || length <= 0) {
    return @"empty packet";
  }

  const uint8_t *bytes = buffer;
  uint8_t version = bytes[0] >> 4;

  if (version == 4) {
    if (length < 20) {
      return [NSString stringWithFormat:@"short IPv4 packet (%d bytes)", length];
    }

    uint8_t headerLength = (bytes[0] & 0x0f) * 4;
    if (headerLength < 20 || length < headerLength) {
      return [NSString stringWithFormat:@"invalid IPv4 header (%d bytes, ihl=%u)", length, headerLength];
    }

    NSString *source = MihomoPacketFlowIPv4AddressString(bytes + 12);
    NSString *destination = MihomoPacketFlowIPv4AddressString(bytes + 16);
    uint8_t protocol = bytes[9];

    if (protocol == IPPROTO_TCP && length >= headerLength + 20) {
      uint16_t sourcePort = (uint16_t)((bytes[headerLength] << 8) | bytes[headerLength + 1]);
      uint16_t destinationPort = (uint16_t)((bytes[headerLength + 2] << 8) | bytes[headerLength + 3]);
      NSString *flags = MihomoPacketFlowTCPFlagsString(bytes[headerLength + 13]);
      return [NSString stringWithFormat:
        @"IPv4 TCP %@:%u -> %@:%u flags=%@ len=%d",
        source,
        sourcePort,
        destination,
        destinationPort,
        flags,
        length];
    }

    if (protocol == IPPROTO_UDP && length >= headerLength + 8) {
      uint16_t sourcePort = (uint16_t)((bytes[headerLength] << 8) | bytes[headerLength + 1]);
      uint16_t destinationPort = (uint16_t)((bytes[headerLength + 2] << 8) | bytes[headerLength + 3]);
      BOOL dnsPacket = sourcePort == 53 || destinationPort == 53;
      if (isDNS != NULL) {
        *isDNS = dnsPacket;
      }
      return [NSString stringWithFormat:
        @"IPv4 UDP %@:%u -> %@:%u%@ len=%d",
        source,
        sourcePort,
        destination,
        destinationPort,
        dnsPacket ? @" dns" : @"",
        length];
    }

    return [NSString stringWithFormat:@"IPv4 proto=%u %@ -> %@ len=%d", protocol, source, destination, length];
  }

  if (version == 6) {
    if (length < 40) {
      return [NSString stringWithFormat:@"short IPv6 packet (%d bytes)", length];
    }

    NSString *source = MihomoPacketFlowIPv6AddressString(bytes + 8);
    NSString *destination = MihomoPacketFlowIPv6AddressString(bytes + 24);
    uint8_t nextHeader = bytes[6];
    NSUInteger transportOffset = 40;

    if (nextHeader == IPPROTO_TCP && length >= (int)(transportOffset + 20)) {
      uint16_t sourcePort = (uint16_t)((bytes[transportOffset] << 8) | bytes[transportOffset + 1]);
      uint16_t destinationPort = (uint16_t)((bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3]);
      NSString *flags = MihomoPacketFlowTCPFlagsString(bytes[transportOffset + 13]);
      return [NSString stringWithFormat:
        @"IPv6 TCP %@:%u -> %@:%u flags=%@ len=%d",
        source,
        sourcePort,
        destination,
        destinationPort,
        flags,
        length];
    }

    if (nextHeader == IPPROTO_UDP && length >= (int)(transportOffset + 8)) {
      uint16_t sourcePort = (uint16_t)((bytes[transportOffset] << 8) | bytes[transportOffset + 1]);
      uint16_t destinationPort = (uint16_t)((bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3]);
      BOOL dnsPacket = sourcePort == 53 || destinationPort == 53;
      if (isDNS != NULL) {
        *isDNS = dnsPacket;
      }
      return [NSString stringWithFormat:
        @"IPv6 UDP %@:%u -> %@:%u%@ len=%d",
        source,
        sourcePort,
        destination,
        destinationPort,
        dnsPacket ? @" dns" : @"",
        length];
    }

    return [NSString stringWithFormat:@"IPv6 next-header=%u %@ -> %@ len=%d", nextHeader, source, destination, length];
  }

  return [NSString stringWithFormat:@"unknown IP version nibble=%u len=%d", version, length];
}

static void MihomoPacketFlowMaybeLogUniqueNonDNSFlow(BOOL fromIOS, NSString *summary) {
  if (summary.length == 0) {
    return;
  }

  __block BOOL shouldLog = NO;
  __block NSUInteger ordinal = 0;
  MihomoPacketFlowPerformLocked(^{
    NSMutableSet<NSString *> *__strong *setRef = fromIOS
      ? &MihomoPacketFlowLoggedReadFlowSummaries
      : &MihomoPacketFlowLoggedWriteFlowSummaries;
    NSUInteger *countRef = fromIOS
      ? &MihomoPacketFlowLoggedReadFlowSummaryCount
      : &MihomoPacketFlowLoggedWriteFlowSummaryCount;

    if (*setRef == nil) {
      *setRef = [NSMutableSet set];
    }

    if ([*setRef containsObject:summary]) {
      return;
    }

    if (*countRef >= MihomoPacketFlowMaxLoggedUniqueNonDNSFlowsPerDirection) {
      return;
    }

    [*setRef addObject:summary];
    *countRef += 1;
    ordinal = *countRef;
    shouldLog = YES;
  });

  if (!shouldLog) {
    return;
  }

  MihomoNativeAppendDiagnosticSharedLog(
    @"info",
    [NSString stringWithFormat:
      @"Packet flow bridge observed non-DNS flow %lu/%lu %@: %@.",
      (unsigned long)ordinal,
      (unsigned long)MihomoPacketFlowMaxLoggedUniqueNonDNSFlowsPerDirection,
      fromIOS ? @"from iOS into the tunnel" : @"written back from the tunnel to iOS",
      summary]
  );
}

static int MihomoPacketFlowReadIntoBufferForReader(void *buffer, int maxLength, uint64_t reader) {
  if (buffer == NULL || maxLength <= 0) {
    return -1;
  }

  __block uint64_t generation = 0;
  __block uint64_t expectedReader = reader;
  MihomoPacketFlowPerformLocked(^{
    generation = MihomoPacketFlowGeneration;
    if (reader == 0) { expectedReader = MihomoPacketReaderGeneration; }
  });
  while (YES) {
    __block MihomoPacketNode *packetNode = NULL;
    __block BOOL shouldWait = NO;
    __block BOOL readingArmed = NO;
    __block NSUInteger queueCountAfterPop = 0;
    MihomoPacketFlowPerformLocked(^{
      if (generation != MihomoPacketFlowGeneration || expectedReader != MihomoPacketReaderGeneration || MihomoPacketFlowBlocked) { return; }
      if (MihomoPacketQueueCount > 0) {
        packetNode = MihomoPacketQueuePopLocked();
        if (packetNode->length <= (NSUInteger)maxLength) {
          MihomoPacketFlowObservedRead = YES;
          MihomoPacketBudget.readBytes += packetNode->length;
        } else {
          MihomoPacketBudget.oversizedPackets++;
        }
        queueCountAfterPop = MihomoPacketQueueCount;
        if (MihomoPacketFlowActive && MihomoPacketFlowReadingArmed && (queueCountAfterPop == 0 || MihomoQueueCanResume(&MihomoPacketBudget))) {
          MihomoPacketFlowScheduleReadLocked();
        }
      } else {
        shouldWait = MihomoPacketFlowActive && MihomoAttachedFlow != nil;
        readingArmed = MihomoPacketFlowReadingArmed;
        if (shouldWait && readingArmed) {
          MihomoPacketFlowScheduleReadLocked();
        }
      }
    });

    if (packetNode != NULL) {
      if (packetNode->length > (NSUInteger)maxLength) {
        free(packetNode->bytes); free(packetNode);
        continue; // Drop the whole datagram. A truncated IP packet is invalid.
      }
      NSUInteger length = packetNode->length;
      memcpy(buffer, packetNode->bytes, length);
      if (MihomoPacketFlowDiagnosticsEnabled()) {
      BOOL isDNS = NO;
      NSString *summary = MihomoPacketFlowPacketSummary(buffer, (int)length, &isDNS);
      if (!MihomoPacketFlowLoggedFirstReadSummary) {
        MihomoPacketFlowLoggedFirstReadSummary = YES;
        MihomoNativeAppendDiagnosticSharedLog(
          @"debug",
          [NSString stringWithFormat:@"Packet flow bridge observed the first packet from iOS into the tunnel: %@.", summary]
        );
      }
      if (!isDNS && !MihomoPacketFlowLoggedFirstNonDNSReadSummary) {
        MihomoPacketFlowLoggedFirstNonDNSReadSummary = YES;
        MihomoNativeAppendDiagnosticSharedLog(
          @"info",
          [NSString stringWithFormat:@"Packet flow bridge observed the first non-DNS packet from iOS into the tunnel: %@.", summary]
        );
      }
      if (!isDNS) {
        MihomoPacketFlowMaybeLogUniqueNonDNSFlow(YES, summary);
      }
      }
      if (packetNode->bytes != NULL) {
        free(packetNode->bytes);
      }
      free(packetNode);
      return (int)length;
    }

    if (!shouldWait) {
      return -1;
    }

    if (!readingArmed) {
      usleep(20 * 1000);
      continue;
    }

    dispatch_semaphore_wait(
      MihomoPacketFlowSemaphore(),
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(250 * NSEC_PER_MSEC))
    );
  }
}

static int MihomoPacketFlowWriteFromBuffer(const void *buffer, int length) {
  if (buffer == NULL || length <= 0) {
    return -1;
  }

  __block NEPacketTunnelFlow *flow = nil;
  __block BOOL active = NO;
  __block uint64_t generation = 0;
  MihomoPacketFlowPerformLocked(^{
    generation = MihomoPacketFlowGeneration;
    flow = MihomoAttachedFlow;
    active = MihomoPacketFlowActive;
  });

  if (!active || flow == nil) {
    return -1;
  }

  const uint8_t *bytes = buffer;
  int family = AF_UNSPEC;
  uint8_t version = bytes[0] >> 4;
  if (version == 4) {
    family = AF_INET;
  } else if (version == 6) {
    family = AF_INET6;
  } else {
    return -1;
  }

  NSData *packet = [NSData dataWithBytes:buffer length:(NSUInteger)length];
  __block BOOL wrotePacket = NO;
  __block BOOL droppedByPolicy = NO;
  MihomoPacketFlowPerformLocked(^{
    if (generation != MihomoPacketFlowGeneration || !MihomoPacketFlowActive || MihomoAttachedFlow != flow) { return; }
    if (MihomoPacketFlowBlocked) {
      MihomoPacketFlowBlockedPackets++;
      droppedByPolicy = YES;
      return;
    }
    if (family == AF_INET6 && MihomoPacketFlowDropIPv6) {
      MihomoPacketFlowDroppedIPv6++;
      droppedByPolicy = YES;
      return;
    }
    wrotePacket = [flow writePackets:@[packet] withProtocols:@[@(family)]];
  });
  if (droppedByPolicy) { return length; }
  if (!wrotePacket) {
    MihomoNativeAppendCriticalSharedLog(
      @"error",
      [NSString stringWithFormat:
        @"Packet flow bridge failed to write a %d-byte packet back to NEPacketTunnelFlow.",
        length]
    );
    return -1;
  }

  MihomoPacketFlowPerformLocked(^{
    if (generation == MihomoPacketFlowGeneration) {
      MihomoPacketFlowObservedSuccessfulWrite = YES;
      MihomoPacketBudget.writtenBytes += length;
    }
  });
  if (MihomoPacketFlowDiagnosticsEnabled()) {
  BOOL isDNS = NO;
  NSString *summary = MihomoPacketFlowPacketSummary(buffer, length, &isDNS);
  if (!MihomoPacketFlowLoggedFirstWriteSummary) {
    MihomoPacketFlowLoggedFirstWriteSummary = YES;
    MihomoNativeAppendDiagnosticSharedLog(
      @"debug",
      [NSString stringWithFormat:@"Packet flow bridge observed the first packet written back from the tunnel to iOS: %@.", summary]
    );
  }
  if (!isDNS && !MihomoPacketFlowLoggedFirstNonDNSWriteSummary) {
    MihomoPacketFlowLoggedFirstNonDNSWriteSummary = YES;
    MihomoNativeAppendDiagnosticSharedLog(
      @"info",
      [NSString stringWithFormat:@"Packet flow bridge observed the first non-DNS packet written back from the tunnel to iOS: %@.", summary]
    );
  }
  if (!isDNS) {
    MihomoPacketFlowMaybeLogUniqueNonDNSFlow(NO, summary);
  }
  }
  return length;
}

int MihomoIOSDebugNoop(void) {
  @autoreleasepool {
    return 1;
  }
}

int MihomoIOSDebugPointerEcho(void *flowPointer) {
  @autoreleasepool {
    return flowPointer != NULL ? 1 : 0;
  }
}

int MihomoIOSDebugBridgeCast(void *flowPointer) {
  @autoreleasepool {
    NEPacketTunnelFlow *flow = (__bridge NEPacketTunnelFlow *)flowPointer;
    return flow != nil ? 1 : 0;
  }
}

void MihomoIOSPacketFlowAttach(void *flowPointer) {
  @autoreleasepool {
    MihomoNativeAppendSharedLog(@"debug", @"C bridge entrypoint entered.");
    NEPacketTunnelFlow *flow = (__bridge NEPacketTunnelFlow *)flowPointer;
    MihomoNativeAppendSharedLog(@"debug", flow != nil ? @"C bridge converted opaque pointer into NEPacketTunnelFlow." : @"C bridge received a null packet flow pointer.");
    MihomoPacketFlowAttach(flow);
    MihomoNativeAppendSharedLog(@"debug", @"C bridge submitted packet flow to the coordinator.");
  }
}

void MihomoIOSPacketFlowClear(void) {
  @autoreleasepool {
    MihomoPacketFlowClear();
  }
}

int MihomoIOSPacketFlowAttached(void) {
  @autoreleasepool {
    return MihomoPacketFlowIsAttached() ? 1 : 0;
  }
}

int MihomoIOSPacketFlowHasObservedRead(void) {
  @autoreleasepool {
    return MihomoPacketFlowHasObservedRead() ? 1 : 0;
  }
}

int MihomoIOSPacketFlowHasObservedSuccessfulWrite(void) {
  @autoreleasepool {
    return MihomoPacketFlowHasObservedSuccessfulWrite() ? 1 : 0;
  }
}

int MihomoIOSReadPacket(void *buffer, int maxLen) {
  @autoreleasepool {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
      MihomoNativeAppendCriticalSharedLog(@"debug", @"Objective-C MihomoIOSReadPacket entered for the first time.");
    });
    return MihomoPacketFlowReadIntoBufferForReader(buffer, maxLen, 0);
  }
}

uint64_t MihomoIOSPacketFlowNewReader(void) {
  @autoreleasepool {
    __block uint64_t reader = 0;
    MihomoPacketFlowPerformLocked(^{ reader = ++MihomoPacketReaderGeneration; });
    dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
    return reader;
  }
}

void MihomoIOSPacketFlowCloseReader(uint64_t reader) {
  @autoreleasepool {
    MihomoPacketFlowPerformLocked(^{
      if (reader == MihomoPacketReaderGeneration) { MihomoPacketReaderGeneration++; }
    });
    dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
  }
}

int MihomoIOSPacketFlowReaderActive(uint64_t reader) {
  @autoreleasepool {
    __block BOOL active = NO;
    MihomoPacketFlowPerformLocked(^{
      active = reader == MihomoPacketReaderGeneration && MihomoPacketFlowActive && !MihomoPacketFlowBlocked;
    });
    return active ? 1 : 0;
  }
}

int MihomoIOSReadPacketForReader(void *buffer, int maxLen, uint64_t reader) {
  @autoreleasepool {
    return MihomoPacketFlowReadIntoBufferForReader(buffer, maxLen, reader);
  }
}

int MihomoIOSWritePacket(const void *buffer, int len) {
  @autoreleasepool {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
      MihomoNativeAppendCriticalSharedLog(@"debug", @"Objective-C MihomoIOSWritePacket entered for the first time.");
    });
    return MihomoPacketFlowWriteFromBuffer(buffer, len);
  }
}

@implementation MihomoPacketFlowObjCBridge

+ (void)attachPacketFlow:(NEPacketTunnelFlow *)flow {
  MihomoNativeAppendCriticalSharedLog(@"debug", @"Objective-C bridge attach entrypoint entered.");
  MihomoPacketFlowAttach(flow);
  MihomoNativeAppendCriticalSharedLog(@"debug", @"Objective-C bridge submitted packet flow to the coordinator.");
}

+ (void)attachPacketFlow:(NEPacketTunnelFlow *)flow dropIPv6:(BOOL)dropIPv6 {
  MihomoPacketFlowAttachWithPolicy(flow, dropIPv6);
}

+ (BOOL)blockAllTrafficForPacketFlow:(NEPacketTunnelFlow *)flow {
  __block BOOL updated = NO;
  MihomoPacketFlowPerformLocked(^{
    if (!MihomoPacketFlowActive || MihomoAttachedFlow != flow) { return; }
    // One-way latch for this attachment. Only an explicit new session may
    // reopen forwarding; late callbacks cannot undo failure protection.
    MihomoPacketFlowBlocked = YES;
    MihomoPacketFlowBlockedPackets += MihomoPacketBudget.count;
    MihomoPacketQueueClearLocked();
    MihomoPacketReaderGeneration++;
    MihomoPacketFlowScheduleReadLocked();
    dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
    updated = YES;
  });
  return updated;
}

+ (BOOL)setDropIPv6:(BOOL)dropIPv6 forPacketFlow:(NEPacketTunnelFlow *)flow {
  __block BOOL updated = NO;
  MihomoPacketFlowPerformLocked(^{
    if (!MihomoPacketFlowActive || MihomoAttachedFlow != flow) { return; }
    if (dropIPv6 && !MihomoPacketFlowDropIPv6) {
      // Remove only queued IPv6; preserve IPv4 order and queue accounting.
      MihomoPacketNode *previous = NULL, *node = MihomoPacketQueueHead;
      while (node != NULL) {
        MihomoPacketNode *next = node->next;
        if (node->length > 0 && (((const uint8_t *)node->bytes)[0] >> 4) == 6) {
          if (previous != NULL) { previous->next = next; } else { MihomoPacketQueueHead = next; }
          if (MihomoPacketQueueTail == node) { MihomoPacketQueueTail = previous; }
          MihomoQueueDidPop(&MihomoPacketBudget, node->length);
          if (MihomoPacketQueueCount > 0) { MihomoPacketQueueCount--; }
          MihomoPacketFlowDroppedIPv6++;
          free(node->bytes); free(node);
        } else { previous = node; }
        node = next;
      }
    }
    MihomoPacketFlowDropIPv6 = dropIPv6;
    MihomoPacketFlowScheduleReadLocked();
    dispatch_semaphore_signal(MihomoPacketFlowSemaphore());
    updated = YES;
  });
  return updated;
}

+ (void)clearAttachment {
  MihomoPacketFlowClear();
}

+ (BOOL)isAttached {
  return MihomoPacketFlowIsAttached();
}

+ (BOOL)hasObservedRead {
  return MihomoPacketFlowHasObservedRead();
}

+ (BOOL)hasObservedSuccessfulWrite {
  return MihomoPacketFlowHasObservedSuccessfulWrite();
}

+ (NSDictionary<NSString *, NSNumber *> *)queueStatistics {
  __block NSDictionary<NSString *, NSNumber *> *result;
  MihomoPacketFlowPerformLocked(^{
    result = @{@"packets": @(MihomoPacketBudget.count), @"bytes": @(MihomoPacketBudget.bytes),
      @"peakBytes": @(MihomoPacketBudget.peakBytes), @"peakPackets": @(MihomoPacketBudget.peakCount),
      @"droppedPackets": @(MihomoPacketBudget.droppedPackets), @"oversizedPackets": @(MihomoPacketBudget.oversizedPackets),
      @"readBytes": @(MihomoPacketBudget.readBytes), @"writtenBytes": @(MihomoPacketBudget.writtenBytes),
      @"blocked": @(MihomoPacketFlowBlocked), @"blockedPackets": @(MihomoPacketFlowBlockedPackets),
      @"dropIPv6": @(MihomoPacketFlowDropIPv6), @"droppedIPv6Packets": @(MihomoPacketFlowDroppedIPv6),
      @"readPaused": @(MihomoPacketFlowReadPaused), @"limitBytes": @(MIHOMO_PACKET_QUEUE_MAX_BYTES)};
  });
  return result;
}

+ (NSDictionary<NSString *, NSNumber *> *)processMemoryStatistics {
  task_vm_info_data_t vmInfo = {0};
  mach_msg_type_number_t vmCount = TASK_VM_INFO_COUNT;
  kern_return_t result = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vmInfo, &vmCount);
  if (result != KERN_SUCCESS) { return @{}; }
  return @{@"physFootprintBytes": @(vmInfo.phys_footprint), @"residentBytes": @(vmInfo.resident_size)};
}

+ (int)debugNoop {
  return MihomoIOSDebugNoop();
}

+ (int)debugPointerEchoForFlow:(NEPacketTunnelFlow *)flow {
  return MihomoIOSDebugPointerEcho((__bridge void *)flow);
}

+ (int)debugBridgeCastForFlow:(NEPacketTunnelFlow *)flow {
  return MihomoIOSDebugBridgeCast((__bridge void *)flow);
}

@end
