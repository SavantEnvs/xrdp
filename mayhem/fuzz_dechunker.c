/* Virtual-channel and dynamic-channel dechunkers: arbitrary chunk sequences. */
#include "config_ac.h"
#include <stdint.h>
#include <stddef.h>

#include "dechunker.h"
#include "log.h"
#include "os_calls.h"
#include "parse.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct log_config *lc = log_config_init_for_console(LOG_LEVEL_NEVER, NULL);
    log_start_from_param(lc);
    log_config_free(lc);
    return 0;
}

/* Input: [mode] then records of [kind][total:u16][len:u16][payload]. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct vc_dechunker *vc = NULL;
    struct dyn_dechunker *dyn = NULL;
    int dynamic;

    if (size < 1)
    {
        return 0;
    }
    dynamic = data[0] & 1;
    ++data;
    --size;

    if (dynamic)
    {
        dyn = dyn_dechunker_init("fuzz");
    }
    else
    {
        vc = vc_dechunker_init("fuzz", 1600);
    }

    while (size >= 5)
    {
        unsigned int kind = data[0];
        int total = data[1] | (data[2] << 8) | ((int)(kind >> 4) << 16);
        size_t len = data[3] | (data[4] << 8);
        struct stream *s;
        struct stream *out;

        data += 5;
        size -= 5;
        if (len > size)
        {
            len = size;
        }
        make_stream(s);
        init_stream(s, (int)len + 1);
        out_uint8a(s, data, len);
        s_mark_end(s);
        s->p = s->data;
        data += len;
        size -= len;

        if (dynamic)
        {
            enum dyn_dechunker_status st;
            if (kind & 1)
            {
                st = dyn_dechunker_process_data_chunk(dyn, s);
            }
            else
            {
                st = dyn_dechunker_process_first_chunk(dyn, s, total);
            }
            (void)dyn_dechunker_pending(dyn);
            if (st == E_DYN_READY)
            {
                out = dyn_dechunker_get_stream(dyn);
                free_stream(out);
            }
        }
        else
        {
            enum vc_dechunker_status st =
                vc_dechunker_process_chunk(vc, s, (int)(kind & 3), total);
            if (st == E_VC_READY)
            {
                out = vc_dechunker_get_stream(vc);
                free_stream(out);
            }
        }
        free_stream(s);
    }

    vc_dechunker_free(vc);
    dyn_dechunker_free(dyn);
    return 0;
}
