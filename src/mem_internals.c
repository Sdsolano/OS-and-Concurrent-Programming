/******************************************************
 * Copyright Grégory Mounié 2018-2022                 *
 * This code is distributed under the GLPv3+ licence. *
 * Ce code est distribué sous la licence GPLv3+.      *
 ******************************************************/

#include <sys/mman.h>
#include <assert.h>
#include <stdint.h>
#include "mem.h"
#include "mem_internals.h"

unsigned long knuth_mmix_one_round(unsigned long in)
{
    return in * 6364136223846793005UL % 1442695040888963407UL;
}

void *mark_memarea_and_get_user_ptr(void *ptr, unsigned long size, MemKind k)
{
    //just to avoid warning
    assert(ptr != NULL);
    assert(size > 0);

    unsigned long total_size = size + 32; // for the beginning and end markers
    //start marker is 16 bytes after ptr
    unsigned long *start_marker = (unsigned long *)ptr;
    
    unsigned long magic_value = knuth_mmix_one_round((unsigned long)ptr);
    magic_value = (magic_value & ~(0b11UL)) | (unsigned long)k; // 2 bits for kind of memory

    // this is gonna be the start marker
    start_marker[0] = size;         
    start_marker[1] = magic_value;              

    // this is gonna be the end marker
    unsigned long *end_marker = (unsigned long *)((char *)ptr + total_size - 16);
    end_marker[0] = magic_value;         
    end_marker[1] = size; 

    // return the user pointer
    return (char *)ptr + 16;
}

Alloc
mark_check_and_get_alloc(void *ptr)
{   
    Alloc a={};

    // get the start of the memory area
    unsigned long *start_marker = (unsigned long *)((char *)ptr - 16);

    // get the start magic value and size
    unsigned long size = start_marker[0];
    unsigned long magic_value = start_marker[1];

    // get the end marker start
    unsigned long *end_marker = (unsigned long *)((char *)ptr + size);

    // get the end magic value and size
    unsigned long size_end = end_marker[1];
    unsigned long magic_value_end = end_marker[0];

    // check if the start and end markers are the same
    assert(size == size_end);
    assert(magic_value == magic_value_end);

    //fill up the Alloc struct
    a.ptr=(void *)start_marker;
    a.size=size;
    a.kind=(MemKind)(magic_value & 0b11);

    return a;
}


unsigned long
mem_realloc_small() {
    assert(arena.chunkpool == 0);
    unsigned long size = (FIRST_ALLOC_SMALL << arena.small_next_exponant);
    arena.chunkpool = mmap(0,
			   size,
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   -1,
			   0);
    if (arena.chunkpool == MAP_FAILED)
	handle_fatalError("small realloc");
    arena.small_next_exponant++;
    return size;
}

unsigned long
mem_realloc_medium() {
    uint32_t indice = FIRST_ALLOC_MEDIUM_EXPOSANT + arena.medium_next_exponant;
    assert(arena.TZL[indice] == 0);
    unsigned long size = (FIRST_ALLOC_MEDIUM << arena.medium_next_exponant);
    assert( size == (1UL << indice));
    arena.TZL[indice] = mmap(0,
			     size*2, // twice the size to allign
			     PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_PRIVATE | MAP_ANONYMOUS,
			     -1,
			     0);
    if (arena.TZL[indice] == MAP_FAILED)
	handle_fatalError("medium realloc");
    // align allocation to a multiple of the size
    // for buddy algo
    arena.TZL[indice] += (size - (((intptr_t)arena.TZL[indice]) % size));
    arena.medium_next_exponant++;
    return size; // lie on allocation size, but never free
}


// used for test in buddy algo
unsigned int
nb_TZL_entries() {
    int nb = 0;
    
    for(int i=0; i < TZL_SIZE; i++)
	if ( arena.TZL[i] )
	    nb ++;

    return nb;
}
