#define _DEFAULT_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "mem_internals.h"
#include "mem.h"
#include "util.h"

void debug_block(struct block_header *b, const char *fmt, ...);

void debug(const char *fmt, ...);

extern inline block_size
size_from_capacity( block_capacity
cap );
extern inline block_capacity
capacity_from_size( block_size
sz );

static bool block_is_big_enough(size_t query, struct block_header *block) { return block->capacity.bytes >= query; }

static size_t pages_count(size_t mem) { return mem / getpagesize() + ((mem % getpagesize()) > 0); }

static size_t round_pages(size_t mem) { return getpagesize() * pages_count(mem); }

static void block_init(void *restrict addr, block_size block_sz, void *restrict next) {
    if(addr == NULL) return;
    *((struct block_header *) addr) = (struct block_header) {
            .next = next,
            .capacity = capacity_from_size(block_sz),
            .is_free = true
    };
}

static size_t region_actual_size(size_t query) { return size_max(round_pages(query), REGION_MIN_SIZE); }

extern inline bool

region_is_invalid(const struct region *r);


static void *map_pages(void const *addr, size_t length, int additional_flags) {

    return mmap((void *) addr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | additional_flags, -1, 0);
}

/*  аллоцировать регион памяти и инициализировать его блоком */
static struct region alloc_region(void const *addr, size_t query) {
    struct region custom_region;
    if(query == REGION_MIN_SIZE){
        query = query + getpagesize();
    }
    query = region_actual_size(query);
    printf("Zu: %zu\n", query);

    custom_region.addr = map_pages(addr, query, MAP_FIXED);
    custom_region.extends = true;
    if(custom_region.addr == MAP_FAILED) {
        custom_region.addr = map_pages(addr, query, MAP_FILE);
        custom_region.extends = false;
    }
    custom_region.size = query;
    block_size bs = (block_size) {custom_region.size};
    if(custom_region.addr != MAP_FAILED) {
        block_init(custom_region.addr, bs, NULL);
    }
    else{
        custom_region.addr = NULL;
    }
    return custom_region;
}

static void *block_after(struct block_header const *block);

void *heap_init(size_t initial) {
    const struct region region = alloc_region(HEAP_START, initial);
    if (region_is_invalid(&region)) return NULL;
    block_size s;
    s.bytes = region.size;
    block_init(region.addr, s, NULL);
    return region.addr;
}

#define BLOCK_MIN_CAPACITY 24

/*  --- Разделение блоков (если найденный свободный блок слишком большой )--- */

static bool block_splittable(struct block_header *restrict block, size_t query) {
    return block->is_free && query + offsetof(
    struct block_header, contents ) +BLOCK_MIN_CAPACITY <= block->capacity.bytes;
}

/*разделение блока, если он слишком большой */
static bool split_if_too_big(struct block_header *block, size_t query) {
    if (!block_splittable(block, query)) {
        return false;
    }
    block_capacity cap;
    cap.bytes = query;
    block_size a = size_from_capacity(block->capacity);
    block_size b = size_from_capacity(cap);
    block_size c;
    c.bytes = a.bytes - b.bytes;
    block_init((void*)block->contents + query,
               c,
               block->next);
    block->capacity = cap;
    block->next = (struct block_header*)((void*)block->contents + query);
    return true;
}


/*  --- Слияние соседних свободных блоков --- */
static void *block_after(struct block_header const *block) {
    return (void *) (block->contents + block->capacity.bytes);
}

static bool blocks_continuous(
        struct block_header const *fst,
        struct block_header const *snd) {
    return (void *) snd == block_after(fst);
}

static bool mergeable(struct block_header const *restrict fst, struct block_header const *restrict snd) {
    return fst != NULL && fst->is_free && snd != NULL &&snd->is_free && blocks_continuous(fst, snd);
}

static bool try_merge_with_next(struct block_header *block) {
    if(block == NULL) return  false;
    if (!mergeable(block, block->next)) {
        return false;
    }
    if(block->next == NULL) return  false;
    block_size sz;
    sz.bytes = size_from_capacity(block->capacity).bytes + size_from_capacity((block->next->capacity)).bytes;
    block_init(block, sz, block->next->next);
    return true;
}


/*  --- ... ecли размера кучи хватает --- */

struct block_search_result {
    enum {
        BSR_FOUND_GOOD_BLOCK, BSR_REACHED_END_NOT_FOUND, BSR_CORRUPTED
    } type;
    struct block_header *block;
};


static struct block_search_result find_good_or_last(struct block_header *restrict block, size_t sz) {
    struct block_header* iterator = block;
    while (1) {
        if(iterator == NULL) return (struct block_search_result){.block = NULL, .type = BSR_CORRUPTED};
        if( try_merge_with_next(iterator) ){ continue;}
        if (iterator->is_free && iterator->capacity.bytes >= sz) {
            struct block_search_result res;
            res.block = iterator;
            res.type = BSR_FOUND_GOOD_BLOCK;
            return res;
        }
        if(iterator->next == NULL){
            struct block_search_result res;
            res.type = BSR_REACHED_END_NOT_FOUND;
            res.block = iterator;
            return res;
        }
        iterator = iterator->next;
    }
    struct block_search_result res;
    res.type = BSR_REACHED_END_NOT_FOUND;
    res.block = block;
    return res;
}

/*  Попробовать выделить память в куче начиная с блока `block` не пытаясь расширить кучу
 Можно переиспользовать как только кучу расширили. */
static struct block_search_result try_memalloc_existing(size_t query, struct block_header *block) {
    struct block_search_result res = find_good_or_last(block, size_max(query, BLOCK_MIN_CAPACITY) );
    if(res.block != NULL){
        split_if_too_big(res.block, size_max(query, BLOCK_MIN_CAPACITY));
        if(res.type == BSR_FOUND_GOOD_BLOCK)
            res.block->is_free = false;
    }
    return res;
}


static struct block_header *grow_heap(struct block_header *restrict last, size_t query) {
    struct region region = alloc_region((void *) (last->contents + last->capacity.bytes), query);
    block_size s;
    s.bytes = region.size;
    block_init(region.addr, s, NULL);
    last->next = (struct block_header*)region.addr;
    if (try_merge_with_next(last)) return last;
    return region.addr;
}

/*  Реализует основную логику malloc и возвращает заголовок выделенного блока */
static struct block_header *memalloc(size_t query, struct block_header *heap_start) {
    struct block_search_result res = try_memalloc_existing(query, heap_start);
    if (res.type == BSR_FOUND_GOOD_BLOCK) {
        split_if_too_big(res.block, size_max(query, BLOCK_MIN_CAPACITY)  );
        res.block->is_free = false;
        return res.block;
    } else {
        struct block_header* iterator = heap_start;
        while (iterator->next != NULL) {
            iterator = iterator->next;
        }
        struct block_header* growBlock = grow_heap(iterator, query);
        res = try_memalloc_existing(query, growBlock);
        if (res.type != BSR_FOUND_GOOD_BLOCK) {
            return NULL;
        }
        split_if_too_big(res.block, size_max(query, BLOCK_MIN_CAPACITY));
        res.block->is_free = false;
        return res.block;
    }
    return NULL;
}

void *_malloc(size_t query) {
    struct block_header *const addr = memalloc(query, (struct block_header *) HEAP_START);
    if (addr) return addr->contents;
    else return NULL;
}

static struct block_header *block_get_header(void *contents) {
    return (struct block_header *) (((uint8_t *) contents) - offsetof(
    struct block_header, contents));
}

void _free(void *mem) {
    if (!mem) return;
    struct block_header *header = block_get_header(mem);
    header->is_free = true;
    try_merge_with_next(header);
}