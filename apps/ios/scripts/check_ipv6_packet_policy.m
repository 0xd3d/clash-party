#import <Foundation/Foundation.h>
#import "MihomoPacketFlowBridge.h"
#include <signal.h>
#include <unistd.h>

// This is a local message-compatible fake, not a real VPN or device flow.
@interface PacketPolicyFakeFlow : NSObject
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, strong) NSMutableArray<NSData *> *queued;
@property(nonatomic, copy) void (^pending)(NSArray<NSData *> *, NSArray<NSNumber *> *);
@property(nonatomic) NSUInteger writes;
- (void)enqueue:(NSArray<NSData *> *)packets;
@end

@implementation PacketPolicyFakeFlow
- (instancetype)init {
  if ((self = [super init])) { _lock = [NSLock new]; _queued = [NSMutableArray new]; }
  return self;
}
- (void)readPacketsWithCompletionHandler:(void (^)(NSArray<NSData *> *, NSArray<NSNumber *> *))completion {
  [_lock lock];
  if (_queued.count == 0) { _pending = [completion copy]; [_lock unlock]; return; }
  NSArray *packets = [_queued copy]; [_queued removeAllObjects]; [_lock unlock];
  completion(packets, @[]);
}
- (void)enqueue:(NSArray<NSData *> *)packets {
  [_lock lock];
  void (^pending)(NSArray<NSData *> *, NSArray<NSNumber *> *) = _pending;
  _pending = nil;
  if (!pending) { [_queued addObjectsFromArray:packets]; }
  [_lock unlock];
  if (pending) { pending(packets, @[]); }
}
- (BOOL)writePackets:(NSArray<NSData *> *)packets withProtocols:(NSArray<NSNumber *> *)protocols {
  [_lock lock]; _writes += packets.count; [_lock unlock]; return YES;
}
@end

static NSData *packet(uint8_t version) {
  NSMutableData *data = [NSMutableData dataWithLength:version == 6 ? 40 : 20];
  ((uint8_t *)data.mutableBytes)[0] = version << 4;
  return data;
}

int main(void) {
  @autoreleasepool {
    alarm(10); // Any blocked regression read fails, rather than hanging CI.
    PacketPolicyFakeFlow *first = [PacketPolicyFakeFlow new];
    NEPacketTunnelFlow *flow = (NEPacketTunnelFlow *)(id)first;
    [MihomoPacketFlowObjCBridge attachPacketFlow:flow dropIPv6:YES];
    uint64_t reader = MihomoIOSPacketFlowNewReader();
    [first enqueue:@[packet(6), packet(4)]];
    uint8_t buffer[128] = {0};
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 20 && buffer[0] == 0x40, @"IPv6 must be discarded before core ingress, preserving IPv4");
    NSData *v6 = packet(6);
    NSCAssert(MihomoIOSWritePacket(v6.bytes, (int)v6.length) == 40, @"Policy drop consumes the datagram");
    NSCAssert(first.writes == 0, @"Disabled IPv6 must not be written to the OS flow");
    NSCAssert([MihomoPacketFlowObjCBridge queueStatistics][@"droppedIPv6Packets"].unsignedLongLongValue == 2, @"Both ingress and egress drops are counted");
    NSCAssert([MihomoPacketFlowObjCBridge setDropIPv6:NO forPacketFlow:flow], @"Current session may enable its family");
    [first enqueue:@[packet(6)]];
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 40 && buffer[0] == 0x60, @"Enabled IPv6 reaches the core");

    // A hot disable discards already queued packets, not just future callbacks.
    [first enqueue:@[packet(4), packet(6)]];
    usleep(20 * 1000);
    NSCAssert([MihomoPacketFlowObjCBridge setDropIPv6:YES forPacketFlow:flow], @"Current session disables atomically");
    [first enqueue:@[packet(4)]];
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 20, @"Hot disable preserves already queued IPv4");
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 20, @"Queued IPv6 cannot escape a disabled policy");

    PacketPolicyFakeFlow *second = [PacketPolicyFakeFlow new];
    NEPacketTunnelFlow *replacement = (NEPacketTunnelFlow *)(id)second;
    [MihomoPacketFlowObjCBridge attachPacketFlow:replacement dropIPv6:YES];
    NSCAssert(![MihomoPacketFlowObjCBridge setDropIPv6:NO forPacketFlow:flow], @"An old session cannot weaken the replacement policy");
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == -1, @"Old core reader expires on replacement");
    reader = MihomoIOSPacketFlowNewReader();
    [second enqueue:@[packet(6), packet(4)]];
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 20, @"Replacement starts with its own disabled policy");
    // A core failure latches the active flow closed before shutdown. Already
    // queued traffic and late writes are consumed, never forwarded or leaked.
    [second enqueue:@[packet(4), packet(6)]];
    usleep(20 * 1000);
    NSCAssert([MihomoPacketFlowObjCBridge blockAllTrafficForPacketFlow:replacement], @"The active flow may retain failure protection");
    NSCAssert([MihomoPacketFlowObjCBridge isAttached], @"Failure must retain the OS flow rather than detach it");
    NSCAssert([MihomoPacketFlowObjCBridge queueStatistics][@"packets"].unsignedLongLongValue == 0, @"Failure clears pending packet storage");
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == -1, @"Failure expires the core reader");
    [second enqueue:@[packet(4), packet(6)]];
    usleep(20 * 1000);
    NSUInteger writesBeforeFailure = second.writes;
    NSData *v4 = packet(4);
    NSCAssert(MihomoIOSWritePacket(v4.bytes, (int)v4.length) == 20 && MihomoIOSWritePacket(v6.bytes, (int)v6.length) == 40, @"Failure consumes both address families");
    NSCAssert(second.writes == writesBeforeFailure, @"Failure must never write to the system flow");
    NSCAssert([MihomoPacketFlowObjCBridge queueStatistics][@"blocked"].boolValue, @"Failure protection is observable");
    NSCAssert([MihomoPacketFlowObjCBridge setDropIPv6:NO forPacketFlow:replacement], @"An IPv6 reload is distinct from failure protection");
    NSCAssert([MihomoPacketFlowObjCBridge queueStatistics][@"blocked"].boolValue, @"A late family update cannot clear failure protection");
    NSCAssert(![MihomoPacketFlowObjCBridge blockAllTrafficForPacketFlow:flow], @"An old session cannot block its replacement");
    PacketPolicyFakeFlow *third = [PacketPolicyFakeFlow new];
    NEPacketTunnelFlow *restarted = (NEPacketTunnelFlow *)(id)third;
    [MihomoPacketFlowObjCBridge attachPacketFlow:restarted dropIPv6:YES];
    NSCAssert(![MihomoPacketFlowObjCBridge blockAllTrafficForPacketFlow:replacement], @"A stale failure cannot poison the explicit new session");
    reader = MihomoIOSPacketFlowNewReader();
    [third enqueue:@[packet(4)]];
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == 20, @"An explicit new session can restore IPv4 forwarding");
    [MihomoPacketFlowObjCBridge clearAttachment];
    NSCAssert(![MihomoPacketFlowObjCBridge setDropIPv6:NO forPacketFlow:replacement], @"A stopped session cannot change policy");
    NSCAssert(MihomoIOSReadPacketForReader(buffer, sizeof(buffer), reader) == -1, @"Stopped readers terminate");
    puts("PASS: IPv6 ingress/egress dropping, IPv4 preservation, hot-disable queue purge, runtime-failure latch/queue purge/late writes, explicit restart and session isolation.");
  }
  return 0;
}
