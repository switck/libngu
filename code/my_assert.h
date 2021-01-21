
#if 1
# undef assert
# define assert(e)      ((void) ((e) ? ((void)0) : my_assert(__FILE__, __LINE__)))

extern void my_assert(const char *fname, int line_num);

#else
# include <assert.h>
#endif


