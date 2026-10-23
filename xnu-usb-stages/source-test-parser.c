/* Production bounded selection logic; no copied parser or device access. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "k70_usb_stage_logic.inc"
static void check(const char *line, bool present, bool valid, unsigned mode)
{
    k70_usb_stage_selection s=k70_usb_stage_select(line,strlen(line)+1);
    assert(s.present==present && s.valid==valid);
    if (valid) assert(s.mode==mode);
}
int main(void)
{
    check("",false,false,0);
    check("k70_probe=3 k70_usb=1",false,false,0);
    check("k70_probe=1 k70_usb=1 k70_usb_wait_ms=60000",false,false,0);
    for (unsigned mode=1;mode<=3;mode++) {
        char line[200]; snprintf(line,sizeof(line),"debug=0 k70_probe=3\tk70_usb_stage=%u k70_usb=1 k70_usb_wait_ms=60000",mode);
        check(line,true,true,mode);
    }
    check("k70_usb_stage=2 k70_probe=3 k70_usb=1 k70_handoff_probe=0",true,true,2);
    const char *bad[]={
        "k70_usb_stage=0 k70_probe=3 k70_usb=1",
        "k70_usb_stage=4 k70_probe=3 k70_usb=1",
        "k70_usb_stage=-1 k70_probe=3 k70_usb=1",
        "k70_usb_stage=01 k70_probe=3 k70_usb=1",
        "k70_usb_stage=0x1 k70_probe=3 k70_usb=1",
        "k70_usb_stage=1x k70_probe=3 k70_usb=1",
        "k70_usb_stage k70_probe=3 k70_usb=1",
        "k70_usb_stagejunk=1 k70_probe=3 k70_usb=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1 k70_usb_stage=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1 k70_probe=3",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1 k70_usb=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1 k70_handoff_probe=0 k70_handoff_probe=0",
        "k70_usb_stage=1 k70_probe=1 k70_usb=1",
        "k70_usb_stage=1 k70_probe=2 k70_usb=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=0",
        "k70_usb_stage=1 k70_probe=3",
        "k70_usb_stage=1 k70_usb=1",
        "k70_usb_stage=1 k70_probe=03 k70_usb=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1 k70_handoff_probe=1",
        "k70_usb_stage=1 k70_probe=3 k70_usb=1\n",
    };
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) check(bad[i],true,false,0);
    char full[96]; memset(full,' ',sizeof(full)); memcpy(full,"k70_usb_stage=1 k70_probe=3 k70_usb=1",35);
    k70_usb_stage_selection s=k70_usb_stage_select(full,sizeof(full)); assert(s.present && !s.valid);
    for (size_t n=0;n<=sizeof(full);n++) { s=k70_usb_stage_select(full,n); assert(s.present && !s.valid); }
    puts("PASS actual stage selection: valid U1/U2/U3, bounded input, duplicates/conflicts/malformed fail closed, absent stage preserves legacy selection");
}
