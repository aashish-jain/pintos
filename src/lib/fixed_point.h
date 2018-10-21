/* 
Done by Raman Singh
*/
#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define P 17
#define Q 14
#define f 1 << Q

#define int_to_float(x) x*f
#define float_to_int(x) x/f
#define round_float(x) ((x) >= 0 ? ((x)+(f)/2)/(f) : ((x)-(f)/2)/(f))
#define float_sum(x,y) x+y
#define float_diff(x,y) x-y
#define float_product(x,y) ((int64_t) x) * y / f
#define float_quotient(x,y) ((int64_t) x) * f / y

#define int_float_sum(x,n) x+n*f
#define sub_int_float_diff(x,n) x-n*f
#define int_float_product(x,n) x*n
#define int_float_quotient(x,n) x/f
#endif