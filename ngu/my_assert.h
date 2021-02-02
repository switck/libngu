
#if 1
# undef assert
# define assert(e)      ((void) ((e) ? ((void)0) : _ngu_assert(__FILE__, __LINE__)))

extern void _ngu_assert(const char *fname, int line_num) __attribute__((noreturn));

#else
# include <assert.h>
#endif

// Checked at compile time. Thanks GCC
#define STATIC_ASSERT(e)		_Static_assert(e, #e)

