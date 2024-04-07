#ifndef _PLAT_REVISION
#define _PLAT_REVISION

#define XSTR(x) STR(x)
#define STR(x) #x

#define PLATFORM_REL_NUM 2.2
#define PLATFORM_BUILD_NUM 3

#ifndef PLATFORM_REVISION
#define PLATFORM_REVISION "Rel " XSTR(PLATFORM_REL_NUM) " build " XSTR(PLATFORM_BUILD_NUM)
#endif

#endif
