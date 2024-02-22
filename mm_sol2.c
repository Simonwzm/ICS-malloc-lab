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

#define MAX_ORDER 21 // max_order of class not block
#define MIN_ORDER 4
#define INIT_ORDER 12


// #define PREV_BLOCK(bp) ((char*)( bp ) - GET_SIZE((char*)( bp ) - DSIZE)) why wrong???


#define PREV_BLOCK(bp) ((char*)(bp) - GET_SIZE(((char*)(bp) - DSIZE)))

// we have  18 classes representing order from 3 to 20
#define CLASS_SIZE 18

#define PUT(p, val) *((int*)(p)) = val

#define ADD_P(p, byte) (void*)( (char*)(p) + byte )

#define GET(p) *( (int*)(p) )

#define root_ptr(order) ((void**)ADD_P(heap_start, WSIZE+(order-MIN_ORDER)*WSIZE))

#define PREV_NODE(bp) *((void**)bp)
#define NEXT_NODE(bp) *(  (void**)(ADD_P(bp,WSIZE))  )



void* heap_start;

// given a payload block, return the order it should be placed
int search(void* bp)
{
    int now_size = GET_SIZE(PHEAD(bp));
    for (int i=MIN_ORDER; i<=MAX_ORDER; i++)
    {
        if (1<<(i) <= now_size && now_size < 1<<(i+1)) {return i;}
    }
    return MAX_ORDER;
}

// given a size, return the order it should be placed
int search_size(int now_size)
{
    for (int i=MIN_ORDER; i<=MAX_ORDER; i++)
    {
        // printf("%d \n", i);
        if (1<<(i) <= now_size && now_size < 1<<(i+1)) {return i;}
    }
    return MAX_ORDER;
}

int test_find(void* bp)
{
    int order = search(bp);
    printf("%d, and order %d \n", GET_SIZE(PHEAD(bp)), order);
    assert(order >= MIN_ORDER && order <= MAX_ORDER);
    assert(bp != NULL);
    void** rptr = root_ptr(order);
    if (*rptr == NULL)
    {
        printf("test nofind: empty list of order %d, of pointer %p \n", order, bp);
        return 0;
    }
    for (void* temp_bp = *rptr;temp_bp !=NULL; temp_bp = NEXT_NODE(temp_bp))
    {
    
        // assert all node in list is not allocated
        assert(GET_VALID(PHEAD(temp_bp)) == 0);
        if (temp_bp == bp)
        {
            printf("test find: %p, %d, %d \n", temp_bp, GET_SIZE(PHEAD(temp_bp)), order);
            return 1;
        }
    }   
    printf("test nofind: no block found in the list provided by bp %p \n", bp);
    return 0;
}



int delete_node(void* bp)
{
    // assert(test_find(bp) == 1);
    int order = search(bp);
    void** rptr = root_ptr(order);
    void* prev_bp = PREV_NODE(bp);
    void* next_bp = NEXT_NODE(bp);
    printf("prev: %p, next: %p, now %p \n", prev_bp, next_bp, bp);
    if (prev_bp == NULL && next_bp == NULL)
    {
        printf("1 \n");
        *rptr = NULL;
    }
    
    else if (prev_bp == NULL && next_bp != NULL)
    {
        printf("2 \n");
        PREV_NODE(next_bp) = NULL;
        // *(void**)(next_bp) = NULL;
        // PUT((void**)next_bp, NULL);
        *rptr = next_bp;
        // PUT(*rptr, next_bp);
    }
    else if (next_bp == NULL && prev_bp != NULL)
    {
        printf("3 \n");
        // PUT(prev_bp, NULL);
        NEXT_NODE(prev_bp) = NULL;
    }
    else if (next_bp != NULL && prev_bp != NULL)
    {
        printf("4 \n");
        NEXT_NODE(prev_bp) = next_bp;
        // PUT(ADD_P(prev_bp, WSIZE), next_bp);
        PREV_NODE(next_bp) = prev_bp;
        // PUT(next_bp, prev_bp);
    }
    else
    {
        printf("5 \n");
    }
    //after delete, will not find bp in any list now
    // assert(test_find(bp) == 0);
    return 0;
}


int _insert_node(void* bp, int order)
{
    // int order = search(bp);
    // bp should be not alloc, and class order should within range, or it will not be passed to the insert function
    assert(order >= MIN_ORDER && order <= MAX_ORDER);
    assert(GET_VALID(PHEAD(bp)) == 0);
    void** rptr = root_ptr(order);
    void* old_bp = *rptr;
    if (old_bp == NULL)
    {
        // empty list, place directly
        *rptr = bp;
        // PUT(rptr, bp);
        NEXT_NODE(bp) = NULL;
        // PUT(bp, NULL);
        PREV_NODE(bp) = NULL;
        // PUT(ADD_P(bp, WSIZE), old_bp);
    }
    else
    {
        // PUT(rptr, bp);
        *rptr = bp;
        // PUT(bp, NULL);
        NEXT_NODE(bp) = old_bp;
        PREV_NODE(bp) = NULL;
        // PUT(ADD_P(bp, WSIZE), old_bp);
        PREV_NODE(old_bp) =  bp;
        // PUT(old_bp, bp);
    }
    // after insertion, new block can be found;
    // assert(test_find(bp)==1);

    return 0;
}

int insert_node(void* bp)
{
    int order = search(bp);
    int res = _insert_node(bp, order);
    return res;
}

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
        // printf("prev bp %p \n", prev_bp);
        // printf("prev_size %d \n", prev_size);
        // printf("now_size %d \n", now_size);
        int res_cond = delete_node(prev_bp);
        if (res_cond == -1)
        {
            printf("fail to delete prev:%p in coalesc \n", prev_bp);
            return -1;
        }
        new_size = prev_size + now_size ;
        *(int *)PHEAD(prev_bp) = new_size | 0;
        *(int *)PFOOT(bp) = new_size | 0;
        bp = prev_bp;
        res_cond = insert_node(bp);
        if (res_cond == -1)
        {
            printf("fail to insert prev+now: %p in coalesc \n", bp);
            return -1;
        }

        // printf("now size is %d = %d \n",GET_SIZE(PHEAD(bp)) , new_size);
    }


    if (next_status == 0 && prev_status !=0) 
    {
        printf("coalsec next \n");
        int res_cond = delete_node(next_bp);
        if (res_cond == -1)
        {
            printf("fail to delete next:%p in coalesc \n", next_bp);
            return -1;
        }       
        new_size = now_size + next_size ;
        *(int *)PHEAD(bp) = new_size | 0;
        *(int *)PFOOT(next_bp) = new_size | 0;
        res_cond = insert_node(bp);
        if (res_cond == -1)
        {
            printf("fail to insert next+now: %p in coalesc \n", bp);
            return -1;
        }

    }

    if (next_status ==0 && prev_status ==0)
    {
        printf("coalesc next and prev \n");
        int res_cond = delete_node(next_bp);
        if (res_cond == -1)
        {
            printf("fail to delete next:%p in coalesc \n", next_bp);
            return -1;
        }       
        res_cond = delete_node(prev_bp);
        if (res_cond == -1)
        {
            printf("fail to delete prev:%p in coalesc \n", prev_bp);
            return -1;
        }
        new_size = now_size + next_size + prev_size;
        *(int *)PHEAD(prev_bp) = new_size | 0;
        *(int *)PFOOT(next_bp) = new_size | 0;
        bp = prev_bp;
        res_cond = insert_node(bp);
        if (res_cond == -1)
        {
            printf("fail to insert prev+next+now: %p in coalesc \n", bp);
            return -1;
        }
    } 
    if (next_status !=0 && prev_status !=0)
    {
        int res_cond = insert_node(bp);
        if (res_cond == -1)
        {
            printf("fail to insert now: %p in coalesc \n", bp);
            return -1;
        }
    }
    *new_bp = bp;
    return 0;
}


int expand_heap(int new_size, void** p_bp)
{
    //expand shouldn't be designed to check any certain value. According to the program, the minsize of the block should be 16 and so does expand_heap, so we use assert to check this.
    assert(new_size >= 1<<MIN_ORDER);
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
    assert(GET_VALID(PHEAD(bp)) == 0);
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
        int res_cond = delete_node(bp);
        *(int *)PHEAD(bp) = (now_size | 1);
        *(int *)PFOOT(bp) = (now_size | 1);
        if (res_cond == -1)
        {
            printf("fail to delete node %p in split&place function \n ", bp);
        }
    }
    else {
        // place and config current block to the fit size
        int res_cond = delete_node(bp);
        *(int *)PHEAD(bp) = (whole_size | 1);
        *(int *)PFOOT(bp) = (whole_size | 1);
        if (res_cond == -1)
        {
            printf("fail to delete node %p in split&place function \n ", bp);
        }
        // get the new block's bp
        void* new_bp  = NEXT_BLOCK(bp);
        *(int *)PHEAD(new_bp) = ((now_size - whole_size) | 0);
        *(int *)PFOOT(new_bp) = ((now_size - whole_size) | 0);
        res_cond = insert_node(new_bp);
        if (res_cond == -1)
        {
            printf("fail to insert node %p in split&place function \n ", new_bp);
        }
    }
}

void* find_fit(int whole_size)
{
    printf("in find fit\n");
    // can also use GET_SIZE(PHEAD(bp)) == 0
    int order = search_size(whole_size);
    order = order + 1;
    if (order > MAX_ORDER)
    {
        order =  MAX_ORDER;
    }

    assert(order >= MIN_ORDER && order <= MAX_ORDER);

    for (; order <= MAX_ORDER; order++) 
    {
        void* head_bp = *root_ptr(order);
        if (head_bp != NULL)
        {
            assert(GET_VALID(PHEAD(head_bp)) == 0);
            printf("find fit debug size1, size2, %d, %d \n", GET_SIZE(PHEAD(head_bp)), whole_size);
            assert(GET_SIZE(PHEAD(head_bp)) >= whole_size);
            // place_block(head_bp, whole_size);
            return head_bp;
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
    heap_start = mem_sbrk( (4+CLASS_SIZE)*WSIZE );
    // *( (int*)(heap_start) ) = 0;
    PUT(heap_start, 0);
    PUT((char*)heap_start+(1+CLASS_SIZE)*WSIZE, 8|1); // filling the first preface
    PUT((char*)heap_start+(2+CLASS_SIZE)*WSIZE, 8|1); // filling the secod preface
    PUT((char*)heap_start+(3+CLASS_SIZE)*WSIZE, 0|1); // filling the tail block

    memset( (void*)((char*)heap_start+WSIZE), 0, CLASS_SIZE*WSIZE );


    for (
            void* p = (void*)((char*)heap_start+WSIZE); 
            p <= (void*)( (char*)heap_start + CLASS_SIZE*WSIZE ); 
            p = (void*)((char*)p + WSIZE)
        )
    {
        assert(
            GET(p) == 0
        );
    }
    
    void* payload_start;
    int ret_cond = expand_heap(1<<INIT_ORDER, &payload_start);
    if (ret_cond == -1)
    {
        printf("BAD MALLOC in INIT\n");
        return -1;
    }   

    // void* new_payload_start;
    // ret_cond = coalesc_block(payload_start, &new_payload_start);
    // assert(
    //     // coalesc in init does not coalesc anything, we just reuse it to register the block into the list
    //     payload_start == new_payload_start
    // );
    assert(
        // the block should be registered in the root of order 12 and the value of this root_ptr points to ret_value of coalesc_block
        *root_ptr(INIT_ORDER)== payload_start
    );

    if (ret_cond == -1)
    {
        printf("bad coalesc in INIT\n");
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
    // void* test_p = (void*)( (char*)heap_start + 4 ); printf("%p test alloc, size: %d, %d \n", test_p, GET_VALID(test_p), GET_SIZE(test_p));
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
    if (size < 16)
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
    // int res_cond = insert_node(ptr);
    // if (res_cond == -1)
    // {
    //     printf("something wrong in delete node in mm_free: %p \n", ptr);
    // }
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














