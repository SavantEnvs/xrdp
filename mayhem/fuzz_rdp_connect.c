#include "fuzz_rdp_common.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    rdp_fuzz_init();
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rdp_fuzz_run(NULL, 0, data, size, 1);
    return 0;
}
