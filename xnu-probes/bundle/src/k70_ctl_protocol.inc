/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * K70CTL/1 bounded framing and reset guard; pure C, no transport or OS calls.
 * The USB poll owner serializes feed/take. Reset guard runs outside USB poll.
 */
#define K70_CTL_LINE_MAX 256U
#define K70_CTL_TOKEN_TTL_MS 10000U
typedef struct {
    uint64_t id, boot, argument;
    bool has_argument;
    char command[32];
} k70_ctl_request;
typedef struct {
    char line[K70_CTL_LINE_MAX+1];
    unsigned used;
    bool invalid, cr, ready;
    uint64_t bad_lines, busy_lines;
    k70_ctl_request pending;
} k70_ctl_mailbox;
typedef struct { uint64_t token, armed_at; bool armed; } k70_ctl_reset_guard;

static inline bool k70_ctl_equal(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static inline bool k70_ctl_hex(const char **text, uint64_t *result)
{
    const char *p=*text; uint64_t value=0; unsigned count=0, digit;
    while (*p && *p!=' ') {
        if (*p>='0' && *p<='9') digit=(unsigned)(*p-'0');
        else if (*p>='a' && *p<='f') digit=(unsigned)(*p-'a'+10);
        else if (*p>='A' && *p<='F') digit=(unsigned)(*p-'A'+10);
        else return false;
        if (++count>16) return false;
        value=(value<<4)|digit; p++;
    }
    if (!count) return false;
    *text=p; *result=value; return true;
}
static inline bool k70_ctl_parse(const char *line, k70_ctl_request *request)
{
    static const char prefix[]="K70CTL 1 "; unsigned i=0, n=0;
    const char *p=line;
    while (prefix[i]) { if (*p++!=prefix[i++]) return false; }
    if (!k70_ctl_hex(&p,&request->id) || !request->id || *p++!=' ') return false;
    if (!k70_ctl_hex(&p,&request->boot) || *p++!=' ') return false;
    while (*p && *p!=' ') {
        char c=*p++;
        if (!((c>='a' && c<='z') || (n && ((c>='0' && c<='9') || c=='-' || c=='_')))) return false;
        if (n>=sizeof(request->command)-1) return false;
        request->command[n++]=c;
    }
    if (!n) return false;
    request->command[n]=0; request->has_argument=false; request->argument=0;
    if (*p) {
        p++; if (!k70_ctl_hex(&p,&request->argument) || *p) return false;
        request->has_argument=true;
    }
    return true;
}
static inline void k70_ctl_feed(k70_ctl_mailbox *box, const uint8_t *data, unsigned bytes)
{
    for (unsigned i=0;i<bytes;i++) {
        uint8_t c=data[i];
        if (c=='\n') {
            box->line[box->used]=0;
            k70_ctl_request request;
            if (box->invalid || !k70_ctl_parse(box->line,&request)) box->bad_lines++;
            else if (box->ready) box->busy_lines++;
            else { box->pending=request; box->ready=true; }
            box->used=0; box->invalid=false; box->cr=false;
        } else if (c=='\r' && !box->cr && !box->invalid) {
            if (box->used>=K70_CTL_LINE_MAX-1U) box->invalid=true;
            else box->cr=true;
        } else if (box->cr || c<0x20 || c>0x7e || box->used>=K70_CTL_LINE_MAX-1U) {
            box->invalid=true;
        } else if (!box->invalid) {
            box->line[box->used++]=(char)c;
        }
    }
}
static inline bool k70_ctl_take(k70_ctl_mailbox *box, k70_ctl_request *request)
{
    if (!box->ready) return false;
    *request=box->pending; box->ready=false; return true;
}
static inline void k70_ctl_arm(k70_ctl_reset_guard *guard, uint64_t token, uint64_t now_ms)
{
    guard->token=token ? token : 1; guard->armed_at=now_ms; guard->armed=true;
}
/* Returns0=denied,1=accepted,2=expired. A confirmation consumes its arm even
 * when the token is wrong. The caller first checks the exact nonzero boot ID.
 */
static inline unsigned k70_ctl_confirm(k70_ctl_reset_guard *guard, uint64_t token, uint64_t now_ms)
{
    if (!guard->armed) return 0;
    guard->armed=false;
    if (now_ms-guard->armed_at>K70_CTL_TOKEN_TTL_MS) return 2;
    return token && token==guard->token ? 1 : 0;
}
