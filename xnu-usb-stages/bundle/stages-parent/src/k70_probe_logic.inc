/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Pure gates shared by the production probe and host negative tests.
 * No hardware, firmware, USB, storage, allocation or time-service access.
 */
#define K70_PROBE_DELAY_SECONDS 4U
#define K70_PROBE_IDLE_LIMIT 1000000ULL
#define K70_PROBE_READ_LIMIT 4294967296ULL
typedef struct {
    uint64_t start, previous, frequency, idle, reads;
} k70_probe_clock;

static inline bool k70_probe_mode_valid(int value)
{ return value >= 1 && value <= 3; }

static inline bool k70_probe_compatible(const void *property, unsigned bytes)
{
    const char *value = property;
    unsigned at = 0;
    bool supported = false;
    if (!value || !bytes || bytes > 256 || value[bytes-1] != 0) return false;
    while (at < bytes) {
        unsigned first = at;
        while (at < bytes && value[at]) at++;
        if (at == first || at == bytes) return false;
        if (at-first == 12 &&
            (!memcmp(value+first, "arm,psci-1.0", 12) ||
             !memcmp(value+first, "arm,psci-0.2", 12))) supported = true;
        at++;
    }
    return supported;
}

static inline unsigned k70_probe_method(const void *property, unsigned bytes)
{
    if (!property || bytes != 4) return 0;
    if (!memcmp(property, "smc", 4)) return 1;
    if (!memcmp(property, "hvc", 4)) return 2;
    return 0;
}

static inline bool k70_probe_status_enabled(const void *property, unsigned bytes)
{
    return property && ((bytes == 3 && !memcmp(property, "ok", 3)) ||
                        (bytes == 5 && !memcmp(property, "okay", 5)));
}

static inline bool k70_probe_clock_begin(k70_probe_clock *clock, uint64_t frequency,
                                         uint64_t counter)
{
    if (frequency < 1000000ULL || frequency > 1000000000ULL) return false;
    *clock = (k70_probe_clock){counter, counter, frequency, 0, 0};
    return true;
}

/* 0=pending, 1=four architectural seconds completed, -1=clock/iteration failure.
 * A stopped counter, a changing frequency, backward/jumping counter or exhausted
 * independent software budget never authorizes a reset.
 */
static inline int k70_probe_clock_step(k70_probe_clock *clock, uint64_t counter,
                                       uint64_t frequency)
{
    if (frequency != clock->frequency || counter < clock->previous ||
        ++clock->reads > K70_PROBE_READ_LIMIT) return -1;
    if (counter == clock->previous) {
        if (++clock->idle > K70_PROBE_IDLE_LIMIT) return -1;
    } else clock->idle = 0;
    uint64_t elapsed = counter-clock->start;
    if (elapsed > clock->frequency*(K70_PROBE_DELAY_SECONDS+1U)) return -1;
    clock->previous = counter;
    return elapsed >= clock->frequency*K70_PROBE_DELAY_SECONDS ? 1 : 0;
}
