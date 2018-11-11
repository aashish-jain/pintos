
#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define P 17
#define Q 14
#define F (1 << Q)

//falready has brackets
//n-> int x,y->float a,b->int
//brackets are key to maintaing intended order
#define ITOF(n) (n*F)
#define FTOI(x) (x/F)
#define F_ROUND(x) ((x) >= 0 ? (((x)+(F)/2)/F) : (((x)-(F)/2)/F))
#define F_SUM(x,y) ((x)+(y))
#define F_DIFF(x,y) ((x)-(y))
#define F_PROD(x,y) (((int64_t) x) * (y) / F)
#define F_DIV(x,y) (((int64_t) x) * F / (y))

#define FI_SUM(x,n) ((x)+((n)*F))
#define FI_DIFF(x,n) ((x)-((n)*F))
#define FI_PROD(x,n) ((x)*(n))
#define FI_DIV(x,n) ((x)/(n))

#endif