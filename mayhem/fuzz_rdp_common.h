/* Shared driver: feeds bytes to a libxrdp server session over a socketpair. */
#include "config_ac.h"
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "log.h"
#include "os_calls.h"
#include "trans.h"
#include "libxrdp.h"

#ifndef FUZZ_INI
#define FUZZ_INI "/mayhem/mayhem/xrdp_fuzz.ini"
#endif

/* Only the server's socket end is closed by trans_delete(); the peer end is ours. */

static int
stub_callback(struct xrdp_process *id, int msg, intptr_t param1, intptr_t param2,
              intptr_t param3, intptr_t param4)
{
    return 0;
}

static void
rdp_fuzz_init(void)
{
    struct log_config *lc = log_config_init_for_console(
        getenv("FUZZ_LOG") ? LOG_LEVEL_DEBUG : LOG_LEVEL_NEVER, NULL);
    log_start_from_param(lc);
    log_config_free(lc);
    signal(SIGPIPE, SIG_IGN);
}

/* Feed prefix+data to a libxrdp session over a socketpair and run the server side. */
static void
rdp_fuzz_run(const uint8_t *prefix, size_t prefix_len,
             const uint8_t *data, size_t size, int process_data)
{
    int sck[2];
    struct trans *trans;
    struct xrdp_session *session;
    size_t total = prefix_len + size;
    uint8_t *buf;

    if (total > 60000 || g_sck_local_socketpair(sck) < 0)
    {
        return;
    }
    buf = (uint8_t *)malloc(total ? total : 1);
    if (prefix_len)
    {
        __builtin_memcpy(buf, prefix, prefix_len);
    }
    if (size)
    {
        __builtin_memcpy(buf + prefix_len, data, size);
    }
    if (send(sck[0], buf, total, 0) != (ssize_t)total)
    {
        free(buf);
        close(sck[0]);
        close(sck[1]);
        return;
    }
    free(buf);
    shutdown(sck[0], SHUT_WR);

    trans = trans_create(TRANS_MODE_UNIX, 16 * 1024, 16 * 1024);
    trans->sck = sck[1];
    trans->type1 = TRANS_TYPE_SERVER;
    trans->status = TRANS_STATUS_UP;

    session = libxrdp_init(NULL, trans, FUZZ_INI);
    session->callback = stub_callback;
    if (libxrdp_process_incoming(session) == 0 && process_data)
    {
        libxrdp_process_data(session, NULL);
    }
    libxrdp_exit(session);
    trans_delete(trans);
    close(sck[0]);
}
