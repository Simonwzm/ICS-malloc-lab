/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

// we use `bp` to show the variable is a pointer pointing to the payload of any blocks
// we use other identifier like `p` to represent pointers pointing to header/footers of blocks

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define MAX(a,b) ((a) > (b)? (a) : (b))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define WSIZE 4

#define DSIZE 8

#define PHEAD(bp) ((char*)bp-WSIZE)

#define GET_SIZE(p) ( *(unsigned int*)p & ~0x7 )

#define GET_VALID(p) ( *(unsigned int*)p & 0x1 )

#define DEFAULT_HEAP 1<<12

#define PFOOT(bp) ((char*)bp + GET_SIZE(PHEAD(bp)) - DSIZE )

#define NEXT_BLOCK(bp) (((char*)( bp ) + GET_SIZE(PHEAD(bp))))

// #define PREV_BLOCK(bp) ((char*)( bp ) - GET_SIZE((char*)( bp ) - DSIZE))

#define PREV_BLOCK(bp) ((char*)(bp) - GET_SIZE(((char*)(bp) - DSIZE)))


void* heap_start;

int coalesc_block(void* bp, void** new_bp) 
{
    printf("in coalesc, current bp is %p. \n", bp);
    // printf("test valid value %d \n", GET_VALID(PHEAD(bp)));
    // printf("test phead value %p \n", PHEAD(bp));
    if (GET_VALID(PHEAD(bp)) != 0)
    {
        printf("Get a non-valid block to coalsec, something wrong.\n");
        return -1;
    }
    // printf("1 \n");
    void* prev_bp = PREV_BLOCK(bp);
    // printf("debug prev_bp: correct= 0xf69a90e8, now = %p \n", prev_bp);
    // printf("2 \n");
    void* next_bp = NEXT_BLOCK(bp);

    // printf("2 \n");
    int prev_status = GET_VALID(PHEAD(prev_bp));
    int next_status = GET_VALID(PHEAD(next_bp));

    int now_size = GET_SIZE(PHEAD(bp)); 
    int prev_size = GET_SIZE(PHEAD(prev_bp));
    int next_size = GET_SIZE(PHEAD(next_bp));

    int new_size = 0;

    if (prev_status == 0 && next_status != 0)
    {
        printf("coalsec prev \n");
        printf("prev bp %p \n", prev_bp);
        printf("prev_size %d \n", prev_size);
        printf("now_size %d \n", now_size);
        new_size = prev_size + now_size ;
        *(int *)PHEAD(prev_bp) = new_size | 0;
        *(int *)PFOOT(bp) = new_size | 0;
        bp = prev_bp;
        printf("now size is %d = %d \n",GET_SIZE(PHEAD(bp)) , new_size);
    }


    if (next_status == 0 && prev_status !=0) 
    {
        printf("coalsec next \n");
        new_size = now_size + next_size ;
        *(int *)PHEAD(bp) = new_size | 0;
        *(int *)PFOOT(next_bp) = new_size | 0;
    }

    if (next_status ==0 && prev_status ==0)
    {
        printf("coalesc next and prev \n");
        new_size = now_size + next_size + prev_size;
        *(int *)PHEAD(prev_bp) = new_size | 0;
        *(int *)PFOOT(next_bp) = new_size | 0;
        bp = prev_bp;
    } 



    *new_bp = bp;
    return 0;
}


int expand_heap(int new_size, void** p_bp)
{
    printf("in expand_heap \n");
    //new_size 是字节数，但是需要双字对齐（8字节）
    new_size = (new_size % 8) ? (new_size/4 + 1)*4 : new_size/4 * 4;

    // perform mem_sbrk
    void* new_bp = mem_sbrk(new_size);

    if (new_bp == NULL)
    {
        printf("expand_heap fail when calling mem_sbrk.\n");
        return -1;
    }
    assert(PHEAD(new_bp) != NULL);
    // printf("new expand start address is %p \n", new_bp);
    // printf("test new_bp head value %p \n", PHEAD(new_bp));
    // printf("test insert value %d \n", new_size | 0);
    *(int *)PHEAD(new_bp) = (new_size | 0);
    // printf("test true insert value %d \n", *(int *)PHEAD(new_bp));
    *(int *)PFOOT(new_bp) = (new_size | 0);
    *(int *)(PFOOT(new_bp) + WSIZE) = (0|1);

    void* coalesc_bp;

    int ret_cond = coalesc_block(new_bp, &coalesc_bp);
    
    if (ret_cond == -1)
    {
        printf("Fail to coalesc, something wrong.\n");
        return -1;
    }
    *p_bp = coalesc_bp;

    return 0;
}

void place_block(void* bp, int whole_size)
{
    printf("in place block \n");
    int now_size = GET_SIZE(PHEAD(bp));
    // guaranteed by find_fit function
    printf("want_size: %d \n", whole_size);
    printf("have_size: %d \n", now_size);
    assert(whole_size <= now_size);
    // 16 = header + footer + 8B_payload = least block that can exist
    if (whole_size > now_size - 16)
    {
        // don't split, only change allocation mark
        *(int *)PHEAD(bp) = (now_size | 1);
        *(int *)PFOOT(bp) = (now_size | 1);
    }
    else {
        // place and config current block to the fit size
        *(int *)PHEAD(bp) = (whole_size | 1);
        *(int *)PFOOT(bp) = (whole_size | 1);
        // get the new block's bp
        void* new_bp  = NEXT_BLOCK(bp);
        *(int *)PHEAD(new_bp) = ((now_size - whole_size) | 0);
        *(int *)PFOOT(new_bp) = ((now_size - whole_size) | 0);
    }
}

void* find_fit(int whole_size)
{
    printf("in find fit\n");
    // can also use GET_SIZE(PHEAD(bp)) == 0
    for (void* bp = (void*)( (char*)(heap_start) + 2*DSIZE); GET_SIZE(PHEAD(bp)) > 0; bp = NEXT_BLOCK(bp))
    {
        // printf("current bp: %p", bp);
        if (
            (GET_SIZE(PHEAD(bp)) >= whole_size) && 
            (GET_VALID(PHEAD(bp)) == 0)
        )
        {
            return bp;
        }
    }
    return NULL;
}

void* best_fit(int whole_size)
{
    // not implemented yet
    return NULL;
}

void* second_fit(int whole_size)
{
    //not implemented yet
    return NULL;
}

void print_alloc()
{
    printf("*******************\n");
    printf("start print list \n");
    printf("*****\n");
    int i = 0;
    void* prev_bp = NULL;
    for (void* bp = (void*)( (char*)(heap_start) + 2*DSIZE); GET_SIZE(PHEAD(bp)) > 0; bp = NEXT_BLOCK(bp))
    {

        printf("current bp: %p, alloc: %d, size: %d \n", bp, GET_VALID(PHEAD(bp)), GET_SIZE(PHEAD(bp)) );
        printf("current bp: %p, alloc: %d, size: %d \n", bp, GET_VALID(PFOOT(bp)), GET_SIZE(PFOOT(bp)) );
        assert(GET_SIZE(PFOOT(bp)) == GET_SIZE(PHEAD(bp)));
        if (i>0)
        {
            printf("test backward: correct=%p, now=%p \n", prev_bp, PREV_BLOCK(bp) );
        }
        i++;
        prev_bp = bp;
        printf("*****\n");
    }

}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    // now heap_list is the bottom of all the memory area we may have 
    void* heap_list = mem_sbrk(4*WSIZE);
    // heap_start remembers where heap begin in memory
    heap_start = heap_list;
    printf("heap_bottom is %p , should be equal to the return value of mem_sbrk %p \n", mem_heap_hi, heap_list);
    if (heap_list == NULL)
    {
        printf("BAD INIT\n");
        return -1;
    }

    *(int*)((char*)heap_list ) =0;
    *(int*)((char*)heap_list + WSIZE) = 8 | 1;
    *(int*)((char*)heap_list + 2*WSIZE) = 8 | 1;
    *(int*)((char*)heap_list + 3*WSIZE) = 0 | 1;
    printf("heap_start %p \n", heap_start);


    //from now on heap_list always points to the second preface block!
    heap_list = (char*)heap_list + 2*WSIZE;
    
    void* test;
    int ret_cond = expand_heap(DEFAULT_HEAP, (void**)(&test));
    if (ret_cond == -1)
    {
        printf("BAD MALLOC in INIT\n");
        return -1;
    }
    return 0;



}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    printf("================== \n");
    printf("in mm_malloc \n");
    void* test_p = (void*)( (char*)heap_start + 4 );
    printf("%p test alloc, size: %d, %d \n", test_p, GET_VALID(test_p), GET_SIZE(test_p));
    // int newsize = ALIGN(size + SIZE_T_SIZE);
    // void *p = mem_sbrk(newsize);
    // if (p == (void *)-1)
	// return NULL;
    // else {
    //     *(size_t *)p = size;
    //     return (void *)((char *)p + SIZE_T_SIZE);
    // }
    
    if (size == 0)
    {
        return NULL;
    }
    int round_size = 0;
    if (size < 8)
    {
        // header_size + foot_size = 8, so whole_size must be 8~16
        round_size = 16;
    }
    else
    {

    round_size = ALIGN(size + SIZE_T_SIZE);
    }
    // int whole_size = round_size + 8;
    int whole_size = round_size;

    void* res_p = find_fit(whole_size);
    if (res_p == NULL)
    {
        // int res_cond = expand_heap(MAX(whole_size, DEFAULT_HEAP), &res_p);
        int res_cond = expand_heap(whole_size, &res_p);
        if (res_cond == -1)
        {
            printf("Something wrong in expand_heap function.\n");
            return NULL;
        }
        if (res_p == NULL)
        {
            printf("Something wrong in expanding heap in malloc function.\n");
            return NULL;
        }
        place_block(res_p, whole_size);
        return res_p;
    }
    else
    {
        place_block(res_p, whole_size);
        return res_p;
    }

}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    printf("================== \n");
    printf("in mm_free \n");
    // print_alloc();
    if (ptr == 0)
    {
        printf("error request \n");
        return;
    }

    int now_size = GET_SIZE(PHEAD(ptr));
    printf("pointer to free is %p, size is %d \n", ptr, now_size);

    
    *(int *)PHEAD(ptr) = now_size | 0;
    *(int *)PFOOT(ptr) = now_size | 0;
    printf("1\n");
    void* new_bp;
    int res_cond = coalesc_block(ptr, &new_bp);
    if (res_cond == -1)
    {
        printf("something wrong in coalesc in mm_free.\n");
    }


}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}














