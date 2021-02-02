#include "py/runtime.h"
#include "my_assert.h"
#include <string.h>

void _ngu_assert(const char *fname, int line_num)
{
    mp_raise_msg_varg(&mp_type_AssertionError, MP_ERROR_TEXT("%s:%d"), fname, line_num);
}


