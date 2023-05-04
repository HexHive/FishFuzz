/* This file is part of GNU cflow.
   Copyright (C) 2008-2019 Sergey Poznyakoff

   GNU cflow is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GNU cflow is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU cflow.  If not, see <http://www.gnu.org/licenses/>. */

#include <cflow.h>

#ifndef CHAR_BIT
# define CHAR_BIT 8
#endif
#define BITS_PER_WORD   (sizeof(unsigned)*CHAR_BIT)

#define WORDSIZE(n)     (((n) + BITS_PER_WORD - 1) / BITS_PER_WORD)
#define SETBIT(x, i)    ((x)[(i)/BITS_PER_WORD] |= (1<<((i) % BITS_PER_WORD)))
#define RESETBIT(x, i)  ((x)[(i)/BITS_PER_WORD] &= ~(1<<((i) % BITS_PER_WORD)))
#define BITISSET(x, i)  (((x)[(i)/BITS_PER_WORD] & (1<<((i) % BITS_PER_WORD))) != 0)

static void
transitive_closure(unsigned *R, int n)
{
     register size_t rowsize;
     register unsigned mask;
     register unsigned *rowj;
     register unsigned *rp;
     register unsigned *rend;
     register unsigned *ccol;
     
     unsigned *relend;
     unsigned *cword;
     unsigned *rowi;
     
     rowsize = WORDSIZE (n) * sizeof (unsigned);
     relend = (unsigned *) ((char *) R + (n * rowsize));
     
     cword = R;
     mask = 1;
     rowi = R;
     while (rowi < relend) {
	  ccol = cword;
	  rowj = R;
                
	  while (rowj < relend) {
	       if (*ccol & mask) {
		    rp = rowi;
		    rend = (unsigned *) ((char *) rowj + rowsize);
                                
		    while (rowj < rend)
			 *rowj++ |= *rp++;
	       } else {
		    rowj = (unsigned *) ((char *) rowj + rowsize);
	       }
	  
	       ccol = (unsigned *) ((char *) ccol + rowsize);
	  }
                
	  mask <<= 1;
	  if (mask == 0) {
	       mask = 1;
	       cword++;
	  }
	  rowi = (unsigned *) ((char *) rowi + rowsize);
     }
}

struct cflow_depmap {
     size_t nrows;
     size_t rowlen;
     unsigned r[1];
};
  
cflow_depmap_t
depmap_alloc(size_t count)
{
     size_t size = (count + BITS_PER_WORD - 1) / BITS_PER_WORD;
     cflow_depmap_t dmap = xzalloc(sizeof(*dmap) - 1 
				   + count * size * sizeof(unsigned));
     dmap->nrows  = count;
     dmap->rowlen = size;
     return dmap;
}

static unsigned *
depmap_rowptr(cflow_depmap_t dmap, size_t row)
{
     return dmap->r + dmap->rowlen * row;
}

void
depmap_set(cflow_depmap_t dmap, size_t row, size_t col)
{
     unsigned *rptr = depmap_rowptr(dmap, row);
     SETBIT(rptr, col);
}

int
depmap_isset(cflow_depmap_t dmap, size_t row, size_t col)
{
     unsigned *rptr = depmap_rowptr(dmap, row);
     return BITISSET(rptr, col);
}

void
depmap_tc(cflow_depmap_t dmap)
{
     transitive_closure(dmap->r, dmap->nrows);
}

