//
// mod NgU
//
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if MICROPY_ENABLE_DYNRUNTIME
#error "Static Only"
#endif

// All submodules here.
extern const mp_obj_module_t mp_module_hash;

STATIC const mp_rom_map_elem_t mp_module_ngu_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ngu) },

    // Constants
    //{ MP_ROM_QSTR(MP_QSTR_ABCD_123), MP_ROM_INT(34) },

    { MP_ROM_QSTR(MP_QSTR_hash), MP_ROM_PTR(&mp_module_hash) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ngu_globals, mp_module_ngu_globals_table);

const mp_obj_module_t mp_module_ngu = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_ngu_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ngu, mp_module_ngu, 1);


