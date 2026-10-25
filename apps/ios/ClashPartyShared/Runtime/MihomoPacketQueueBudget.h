#ifndef MIHOMO_PACKET_QUEUE_BUDGET_H
#define MIHOMO_PACKET_QUEUE_BUDGET_H
#include <stddef.h>
#include <stdint.h>

// Limits cover packet payloads owned by this bridge, independently of OS buffers.
#define MIHOMO_PACKET_QUEUE_MAX_BYTES (4u * 1024u * 1024u)
#define MIHOMO_PACKET_QUEUE_MAX_COUNT 4096u
#define MIHOMO_PACKET_QUEUE_HIGH_BYTES (3u * 1024u * 1024u)
#define MIHOMO_PACKET_QUEUE_HIGH_COUNT 3072u
#define MIHOMO_PACKET_QUEUE_LOW_BYTES (2u * 1024u * 1024u)
#define MIHOMO_PACKET_QUEUE_LOW_COUNT 2048u

typedef struct {
  size_t bytes, count, peakBytes, peakCount;
  uint64_t droppedPackets, oversizedPackets, readBytes, writtenBytes;
} MihomoPacketQueueBudget;

static inline int MihomoQueueCanAppend(const MihomoPacketQueueBudget *budget, size_t length) {
  return length > 0 && budget->count < MIHOMO_PACKET_QUEUE_MAX_COUNT
    && length <= MIHOMO_PACKET_QUEUE_MAX_BYTES - budget->bytes;
}
static inline void MihomoQueueDidAppend(MihomoPacketQueueBudget *budget, size_t length) {
  budget->bytes += length; budget->count++;
  if (budget->bytes > budget->peakBytes) budget->peakBytes = budget->bytes;
  if (budget->count > budget->peakCount) budget->peakCount = budget->count;
}
static inline void MihomoQueueDidPop(MihomoPacketQueueBudget *budget, size_t length) {
  budget->bytes = length <= budget->bytes ? budget->bytes - length : 0;
  if (budget->count > 0) budget->count--;
}
static inline int MihomoQueueShouldPause(const MihomoPacketQueueBudget *budget) {
  return budget->bytes >= MIHOMO_PACKET_QUEUE_HIGH_BYTES || budget->count >= MIHOMO_PACKET_QUEUE_HIGH_COUNT;
}
static inline int MihomoQueueCanResume(const MihomoPacketQueueBudget *budget) {
  return budget->bytes <= MIHOMO_PACKET_QUEUE_LOW_BYTES && budget->count <= MIHOMO_PACKET_QUEUE_LOW_COUNT;
}
#endif
