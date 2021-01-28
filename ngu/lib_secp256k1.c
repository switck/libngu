#ifndef NO_QSTR

# ifndef HAVE_CONFIG_H
#  define HAVE_CONFIG_H
# endif

# define USE_EXTERNAL_DEFAULT_CALLBACKS

// use micropython mem management
#define malloc     m_malloc
#define free       m_free

# include "src/secp256k1.c"
#endif
