#ifndef __ARRAY_H__
#define __ARRAY_H__

#define ARRAY_DEFAULT_CAP (16)

typedef struct {
    void *data;
    int   elem_size;
    int   used;
    int   capacity;
    int   should_free;
} array_t;

array_t _array_make(int elem_size);
array_t _array_make_with_cap(int elem_size, int initial_cap);
void _array_free(array_t *array);
void * _array_push(array_t *array, void *elem);
void * _array_push_n(array_t *array, void *elems, int n);
void * _array_next_elem(array_t *array);
void * _array_insert(array_t *array, int idx, void *elem);
void _array_delete(array_t *array, int idx);
void _array_zero_term(array_t *array);
void _array_grow_if_needed(array_t *array);
void _array_copy(array_t *dst, array_t *src);

#define array_make(T) \
    (_array_make(sizeof(T)))

#define array_make_with_cap(T, cap) \
    (_array_make_with_cap(sizeof(T), (cap)))

#define array_free(array) \
    (_array_free(&(array)))

#define array_len(array) \
    ((array).used)

#define array_next_elem(array) \
    (_array_next_elem(&(array)))

#define array_push(array, elem) \
    (_array_push(&(array), &(elem)))

#define array_push_n(array, elems, n) \
    (_array_push_n(&(array), (elems), (n)))

#define array_insert(array, idx, elem) \
    (_array_insert(&(array), idx, &(elem)))

#define array_delete(array, idx) \
    (_array_delete(&(array), idx))

#define array_pop(array) \
    (_array_delete(&(array), (array).used - 1))

#define array_clear(array) \
    ((array).used = 0)

#define array_item(array, idx) \
    (void*)(((char*)(array).data + ((array).elem_size * (idx))))

#define array_last(array) \
    ((array).used ? (void*)((char*)(array).data + ((array).elem_size * ((array).used - 1))) : NULL)


#define array_traverse(array, it)                                                             \
    for (it = (__typeof(it))(array).data;                                                     \
         it < (__typeof(it))((char*)(array).data + ((array).used * (array).elem_size));       \
         it += 1)

#define array_traverse_from(array, it, starting_idx)                                          \
    for (it = (__typeof(it))((char*)(array).data + ((starting_idx) * (array).elem_size));     \
         it < (__typeof(it))((char*)(array).data + ((array).used * (array).elem_size));       \
         it += 1)

#define array_rtraverse(array, it)                                                            \
    for (it = (__typeof(it))((char*)(array).data + (((array).used - 1) * (array).elem_size)); \
         (array).used && it >= (__typeof(it))((array).data);                                  \
         it -= 1)

#define array_data(array) ((array).data)

#define array_zero_term(array) (_array_zero_term(&(array)))

#define array_grow_if_needed(array) \
    (_array_grow_if_needed(&(array)))

#define array_copy(dst, src) \
    (_array_copy(&(dst), &(src)))

#endif
