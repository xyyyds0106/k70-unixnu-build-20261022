/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Bounded, exact diagnostic command-line selection. No architectural access.
 * A present but invalid stage suppresses every legacy early reset probe.
 */
typedef struct {
    bool present, valid;
    unsigned mode;
} k70_usb_stage_selection;

static inline bool k70_usb_stage_prefix(const char *text, size_t bytes,
                                        const char *key, size_t key_bytes)
{
    if (bytes < key_bytes) return false;
    for (size_t i = 0; i < key_bytes; i++) if (text[i] != key[i]) return false;
    return true;
}
static inline bool k70_usb_stage_digit(const char *text, size_t bytes,
                                       size_t key_bytes, unsigned *value)
{
    if (bytes != key_bytes + 2 || text[key_bytes] != '=' ||
        text[key_bytes + 1] < '0' || text[key_bytes + 1] > '3') return false;
    *value = (unsigned)(text[key_bytes + 1] - '0');
    return true;
}
static inline k70_usb_stage_selection k70_usb_stage_select(const char *line,
                                                           size_t capacity)
{
    k70_usb_stage_selection result = {false, false, 0};
    unsigned stages = 0, probes = 0, usbs = 0, handoffs = 0;
    unsigned probe = 0, usb = 0, handoff = 0;
    bool bad = false;
    size_t end = 0;
    while (end < capacity && line[end]) end++;
    bool terminated = end < capacity;
    for (size_t at = 0; at < end;) {
        while (at < end && (line[at] == ' ' || line[at] == '\t')) at++;
        size_t begin = at;
        while (at < end && line[at] != ' ' && line[at] != '\t') at++;
        size_t bytes = at - begin;
        const char *token = line + begin;
        if (!bytes) continue;
        if (k70_usb_stage_prefix(token, bytes, "k70_usb_stage", 13)) {
            stages++;
            if (!k70_usb_stage_digit(token, bytes, 13, &result.mode)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_probe", 9)) {
            probes++;
            if (!k70_usb_stage_digit(token, bytes, 9, &probe)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_handoff_probe", 17)) {
            handoffs++;
            if (!k70_usb_stage_digit(token, bytes, 17, &handoff)) bad = true;
        } else if (k70_usb_stage_prefix(token, bytes, "k70_usb", 7) &&
                   (bytes == 7 || token[7] == '=')) {
            usbs++;
            if (!k70_usb_stage_digit(token, bytes, 7, &usb)) bad = true;
        }
    }
    result.present = stages != 0 || !terminated;
    result.valid = result.present && terminated && !bad && stages == 1 &&
        result.mode >= 1 && result.mode <= 3 && probes == 1 && probe == 3 &&
        usbs == 1 && usb == 1 && (handoffs == 0 || (handoffs == 1 && handoff == 0));
    return result;
}
