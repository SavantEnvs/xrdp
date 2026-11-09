/* libipm: parse arbitrary bytes as an IPM message stream (sesman <-> xrdp control protocol). */
#include "config_ac.h"
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "libipm.h"
#include "log.h"
#include "os_calls.h"
#include "trans.h"

static const char *
msgno_to_str(unsigned short msgno)
{
    return "msg";
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct log_config *lc = log_config_init_for_console(LOG_LEVEL_NEVER, NULL);
    log_start_from_param(lc);
    log_config_free(lc);
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

/* Consume one value of the type found at the head of the message. */
static enum libipm_status
parse_one(struct trans *trans, unsigned int index)
{
    union
    {
        unsigned char y;
        int b;
        uint16_t q;
        uint32_t u;
        uint64_t t;
        char *s;
        int h;
    } v;
    char buf[16];
    struct libipm_fsb fsb = { buf, (index & 1) ? 4 : 16 };
    char c = libipm_msg_in_peek_type(trans);

    switch (c)
    {
        case 'y':
            return libipm_msg_in_parse(trans, "y", &v.y);
        case 'b':
            return libipm_msg_in_parse(trans, "b", &v.b);
        case 'n':
            return libipm_msg_in_parse(trans, "n", &v.q);
        case 'q':
            return libipm_msg_in_parse(trans, "q", &v.q);
        case 'i':
            return libipm_msg_in_parse(trans, "i", &v.u);
        case 'u':
            return libipm_msg_in_parse(trans, "u", &v.u);
        case 'x':
            return libipm_msg_in_parse(trans, "x", &v.t);
        case 't':
            return libipm_msg_in_parse(trans, "t", &v.t);
        case 's':
            return libipm_msg_in_parse(trans, "s", &v.s);
        case 'h':
            return libipm_msg_in_parse(trans, "h", &v.h);
        case 'B':
            return libipm_msg_in_parse(trans, "B", &fsb);
        default:
            return libipm_msg_in_parse(trans, "?");
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sck[2];
    struct trans *trans;
    int msgs;

    if (size > 40000 || g_sck_local_socketpair(sck) < 0)
    {
        return 0;
    }
    if (size > 0 && send(sck[0], data, size, 0) != (ssize_t)size)
    {
        close(sck[0]);
        close(sck[1]);
        return 0;
    }
    shutdown(sck[0], SHUT_WR);

    trans = trans_create(TRANS_MODE_UNIX, 128, 128);
    trans->sck = sck[1];
    trans->type1 = TRANS_TYPE_SERVER;
    trans->status = TRANS_STATUS_UP;
    libipm_init_trans(trans, LIBIPM_FAC_SCP, msgno_to_str);

    for (msgs = 0; msgs < 16; ++msgs)
    {
        unsigned int i;
        libipm_msg_in_reset(trans);
        if (libipm_msg_in_wait_available(trans) != E_LI_SUCCESS)
        {
            break;
        }
        (void)libipm_msg_in_get_msgno(trans);
        for (i = 0; i < 64; ++i)
        {
            if (parse_one(trans, i) != E_LI_SUCCESS)
            {
                break;
            }
        }
        libipm_msg_in_reset(trans);
    }

    trans_delete(trans);
    close(sck[0]);
    return 0;
}
