#include <stdint.h>
#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

#ifdef __cplusplus
extern "C" {
#endif

int MihomoIOSDebugNoop(void);
int MihomoIOSDebugPointerEcho(void * _Nullable flow);
int MihomoIOSDebugBridgeCast(void * _Nullable flow);
void MihomoIOSNativeLog(const char * _Nullable level, const char * _Nullable message);
void MihomoIOSPacketFlowAttach(void * _Nullable flow);
void MihomoIOSPacketFlowClear(void);
int MihomoIOSPacketFlowAttached(void);
int MihomoIOSPacketFlowHasObservedRead(void);
int MihomoIOSPacketFlowHasObservedSuccessfulWrite(void);
int MihomoIOSReadPacket(void * _Nullable buffer, int maxLen);
int MihomoIOSWritePacket(const void * _Nullable buffer, int len);
uint64_t MihomoIOSPacketFlowNewReader(void);
void MihomoIOSPacketFlowCloseReader(uint64_t reader);
int MihomoIOSPacketFlowReaderActive(uint64_t reader);
int MihomoIOSReadPacketForReader(void * _Nullable buffer, int maxLen, uint64_t reader);

#ifdef __cplusplus
}
#endif

@interface MihomoPacketFlowObjCBridge : NSObject

+ (void)attachPacketFlow:(NEPacketTunnelFlow * _Nullable)flow;
+ (void)attachPacketFlow:(NEPacketTunnelFlow * _Nullable)flow dropIPv6:(BOOL)dropIPv6;
+ (BOOL)blockAllTrafficForPacketFlow:(NEPacketTunnelFlow * _Nonnull)flow NS_SWIFT_NAME(blockAllTraffic(for:));
+ (BOOL)setDropIPv6:(BOOL)dropIPv6 forPacketFlow:(NEPacketTunnelFlow * _Nonnull)flow;
+ (void)clearAttachment;
+ (BOOL)isAttached;
+ (BOOL)hasObservedRead;
+ (BOOL)hasObservedSuccessfulWrite;
+ (NSDictionary<NSString *, NSNumber *> * _Nonnull)queueStatistics;
+ (NSDictionary<NSString *, NSNumber *> * _Nonnull)processMemoryStatistics;
+ (int)debugNoop;
+ (int)debugPointerEchoForFlow:(NEPacketTunnelFlow * _Nullable)flow;
+ (int)debugBridgeCastForFlow:(NEPacketTunnelFlow * _Nullable)flow;

@end
