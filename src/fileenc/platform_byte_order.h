#ifndef _PLATFORM_BYTE_ORDER_H_
#define _PLATFORM_BYTE_ORDER_H_

/*
    To obtain the highest speed on processors with 32-bit words, this code 
    needs to determine the order in which bytes are packed into such words.
    The following block of code is an attempt to capture the most obvious 
    ways in which various environemnts specify their endian definitions. 
    It may well fail, in which case the definitions will need to be set by 
    editing at the points marked **** EDIT HERE IF NECESSARY **** below.
*/
/*  PLATFORM SPECIFIC INCLUDES */

#if defined( __FreeBSD__ ) || defined( __OpenBSD__ )
#  include <sys/endian.h>
#elif defined( BSD ) && ( BSD >= 199103 )
#  include <machine/endian.h>
#elif (defined( __GNUC__ ) || defined( __GNU_LIBRARY__ )) && !defined( WIN32 )
#  include <endian.h>
#  include <byteswap.h>
#elif defined( linux )
#  include <endian.h>
#endif

/*  BYTE ORDER IN 32-BIT WORDS

    To obtain the highest speed on processors with 32-bit words, this code
    needs to determine the byte order of the target machine. The following 
    block of code is an attempt to capture the most obvious ways in which 
    various environemnts define byte order. It may well fail, in which case 
    the definitions will need to be set by editing at the points marked 
    **** EDIT HERE IF NECESSARY **** below.  My thanks to Peter Gutmann for 
    some of these defines (from cryptlib).
*/

#define PLATFORM_BYTE_ORDER_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define PLATFORM_BYTE_ORDER_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if defined( __alpha__ ) || defined( __alpha ) || defined( i386 )       ||   \
    defined( __i386__ )  || defined( _M_I86 )  || defined( _M_IX86 )    ||   \
    defined( __OS2__ )   || defined( sun386 )  || defined( __TURBOC__ ) ||   \
    defined( vax )       || defined( vms )     || defined( VMS )        ||   \
    defined( __VMS ) 

#define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN

#endif

#if defined( AMIGA )    || defined( applec )  || defined( __AS400__ )  ||   \
    defined( _CRAY )    || defined( __hppa )  || defined( __hp9000 )   ||   \
    defined( ibm370 )   || defined( mc68000 ) || defined( m68k )       ||   \
    defined( __MRC__ )  || defined( __MVS__ ) || defined( __MWERKS__ ) ||   \
    defined( sparc )    || defined( __sparc)  || defined( SYMANTEC_C ) ||   \
    defined( __TANDEM ) || defined( THINK_C ) || defined( __VMCMS__ )

#define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN

#endif

/*  if the platform is still not known, try to find its byte order  */
/*  from commonly used definitions in the headers included earlier  */

#if !defined(PLATFORM_BYTE_ORDER)

#  if defined(LITTLE_ENDIAN) || defined(BIG_ENDIAN)
#   if    defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#     define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#   elif !defined(LITTLE_ENDIAN) &&  defined(BIG_ENDIAN)
#     define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#   elif defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#     define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#   elif defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
#     define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#   endif

#  elif defined(_LITTLE_ENDIAN) || defined(_BIG_ENDIAN)
#    if    defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#    elif !defined(_LITTLE_ENDIAN) &&  defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _LITTLE_ENDIAN)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#    endif

#  elif defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__)
#    if    defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#    elif !defined(__LITTLE_ENDIAN__) &&  defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#    endif

#  elif 0     /* **** EDIT HERE IF NECESSARY **** */
#    define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN

#  elif 0     /* **** EDIT HERE IF NECESSARY **** */
#    define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN

#  elif (('1234' >> 24) == '1')
#    define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_LITTLE_ENDIAN

#  elif (('4321' >> 24) == '1')
#    define PLATFORM_BYTE_ORDER PLATFORM_BYTE_ORDER_BIG_ENDIAN
#  endif

#endif

#if !defined(PLATFORM_BYTE_ORDER)
#  error Please edit platform_byte_order.h (line 98 or 101) to set the platform byte order
#endif

// #if   (PLATFORM_BYTE_ORDER == PLATFORM_BYTE_ORDER_LITTLE_ENDIAN)
// #  error "BIG_ENDIAN"
// #elif (PLATFORM_BYTE_ORDER == PLATFORM_BYTE_ORDER_BIG_ENDIAN)
// #  error "LITTLE_ENDIAN"
// #else
// #  error "UNKNOWN_ENDIAN"
// #endif

#endif
