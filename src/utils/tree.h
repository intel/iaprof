/*
 * tree.h
 * Brandon Kammerdiener
 * September, 2018
 *
 * "generic", type-safe Red/Black tree implementation for C
 *
 * adapted from https://github.com/mirek/rb_tree
 */

#ifndef _TREE_H_
#define _TREE_H_

#include <stdint.h>
#include <stdlib.h>

#ifndef TREE_MALLOC_FN
#define TREE_MALLOC_FN malloc
#endif

#ifndef TREE_FREE_FN
#define TREE_FREE_FN free
#endif

#define tree_make(K_T, V_T) (CAT2(tree(K_T, V_T), _make)())
#define tree_len(t) (t->_len)
#define tree_free(t) (t->_free((t)))
#define tree_lookup(t, k) (t->_lookup((t), (k)))
#define tree_insert(t, k, v) (t->_insert((t), (k), (v)))
#define tree_delete(t, k) (t->_delete((t), (k)))
#define tree_begin(t) (t->_begin((t)))
#define tree_last(t) (t->_last((t)))
#define tree_geq(t, k) (t->_geq((t), (k)))
#define tree_gtr(t, k) (t->_gtr((t), (k)))

#define tree_it_key(it) ((it)._node->_key)
#define tree_it_val(it) ((it)._node->_val)
#define tree_it_next(it) ((it)._next(&(it)))
#define tree_it_good(it) ((it)._node != NULL)
#define tree_it_prev(it)                                                       \
    do {                                                                       \
        if ((it)._node == tree_begin((it._t))._node) {                         \
            (it)._node = NULL;                                                 \
        } else if (tree_it_good(it)) {                                         \
            (it)._prev(&(it));                                                 \
        } else {                                                               \
            (it) = tree_last((it)._t);                                         \
        }                                                                      \
    } while (0)
#define tree_it_equ(it1, it2)                                                  \
    ((it1)._node == (it2)._node && (it1)._t == (it2)._t)
#define tree_traverse(t, it)                                                   \
    for ((it) = tree_begin(t); tree_it_good((it)); tree_it_next((it)))

#define STR(x) _STR(x)
#define _STR(x) #x

#define CAT2(x, y) _CAT2(x, y)
#define _CAT2(x, y) x##y

#define CAT3(x, y, z) _CAT3(x, y, z)
#define _CAT3(x, y, z) x##y##z

#define CAT4(a, b, c, d) _CAT4(a, b, c, d)
#define _CAT4(a, b, c, d) a##b##c##d

#define _tree_node(K_T, V_T) CAT4(_tree_node_, K_T, _, V_T)
#define tree_node(K_T, V_T) CAT4(tree_node_, K_T, _, V_T)
#define _tree_it(K_T, V_T) CAT4(_tree_it_, K_T, _, V_T)
#define tree_it(K_T, V_T) CAT4(tree_it_, K_T, _, V_T)
#define _tree(K_T, V_T) CAT4(_tree_, K_T, _, V_T)
#define tree(K_T, V_T) CAT4(tree_, K_T, _, V_T)
#define tree_pretty_name(K_T, V_T) ("tree(" CAT3(K_T, ", ", V_T) ")")

#define _TN_IS_RED(tn) ((tn) ? (tn)->_red : 0)

#define _TI_FROM_TN(K_T, V_T, t, tn)                                           \
    ((tree_it(K_T, V_T)){._t = (t),                                            \
                         ._node = (tn),                                        \
                         ._next = CAT2(tree_it(K_T, V_T), _next),              \
                         ._prev = CAT2(tree_it(K_T, V_T), _prev)})

#define use_tree(K_T, V_T)                                                     \
    typedef struct _tree_node(K_T, V_T) {                                      \
        int _red;                                                              \
        struct _tree_node(K_T, V_T) * _children[2], *_parent;                  \
        K_T _key;                                                              \
        V_T _val;                                                              \
    }                                                                          \
    *tree_node(K_T, V_T);                                                      \
                                                                               \
    struct _tree_it(K_T, V_T);                                                 \
                                                                               \
    typedef void (*CAT2(tree_it(K_T, V_T), _next_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
    typedef void (*CAT2(tree_it(K_T, V_T), _prev_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
                                                                               \
    struct _tree(K_T, V_T);                                                    \
                                                                               \
    typedef struct _tree_it(K_T, V_T) {                                        \
        struct _tree(K_T, V_T) * _t;                                           \
        tree_node(K_T, V_T) _node;                                             \
        CAT2(tree_it(K_T, V_T), _next_t)                                       \
        _next;                                                                 \
        CAT2(tree_it(K_T, V_T), _prev_t)                                       \
        _prev;                                                                 \
    }                                                                          \
    tree_it(K_T, V_T);                                                         \
                                                                               \
    typedef void (*CAT2(tree(K_T, V_T), _free_t))(struct _tree(K_T, V_T) *);   \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _lookup_t))(              \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _insert_t))(              \
        struct _tree(K_T, V_T) *, K_T, V_T);                                   \
    typedef int (*CAT2(tree(K_T, V_T), _delete_t))(struct _tree(K_T, V_T) *,   \
                                                   K_T);                       \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _begin_t))(               \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _last_t))(                \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _geq_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _gtr_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
                                                                               \
    typedef struct _tree(K_T, V_T) {                                           \
        tree_node(K_T, V_T) _root, _beg;                                       \
        uint64_t _len;                                                         \
                                                                               \
        CAT2(tree(K_T, V_T), _free_t)  _free;                                  \
        CAT2(tree(K_T, V_T), _lookup_t)  _lookup;                              \
        CAT2(tree(K_T, V_T), _insert_t)  _insert;                              \
        CAT2(tree(K_T, V_T), _delete_t)  _delete;                              \
        CAT2(tree(K_T, V_T), _begin_t)  _begin;                                \
        CAT2(tree(K_T, V_T), _last_t)  _last;                                  \
        CAT2(tree(K_T, V_T), _geq_t)  _geq;                                    \
        CAT2(tree(K_T, V_T), _geq_t)  _gtr;                                    \
    }                                                                          \
    *tree(K_T, V_T);                                                           \
                                                                               \
    /* tree node */                                                            \
    static inline tree_node(K_T, V_T)                                          \
        CAT2(tree_node(K_T, V_T), _make)(K_T key, V_T val) {                   \
        tree_node(K_T, V_T) node =                                             \
            (tree_node(K_T, V_T))                                              \
                TREE_MALLOC_FN(sizeof(struct _tree_node(K_T, V_T)));           \
                                                                               \
        node->_red = 1;                                                        \
        node->_children[0] = node->_children[1] = node->_parent = NULL;        \
        node->_key = key;                                                      \
        node->_val = val;                                                      \
                                                                               \
        return node;                                                           \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_node(K_T, V_T),                               \
                            _free)(tree_node(K_T, V_T) node) {                 \
        if (node) {                                                            \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[0]);              \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[1]);              \
            TREE_FREE_FN(node);                                                \
        }                                                                      \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate)(      \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            result = node->_children[!dir];                                    \
            node->_children[!dir] = result->_children[dir];                    \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result->_children[dir] = node;                                     \
            if (result->_children[dir])                                        \
                result->_children[dir]->_parent = result;                      \
            node->_red = 1;                                                    \
            result->_red = 0;                                                  \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate2)(     \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            node->_children[!dir] = CAT2(tree_node(K_T, V_T), _rotate)(        \
                node->_children[!dir], !dir);                                  \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result = CAT2(tree_node(K_T, V_T), _rotate)(node, dir);            \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    /* tree it */                                                              \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _next)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node)                                                             \
            return;                                                            \
                                                                               \
        if (node->_children[1]) {                                              \
            node = node->_children[1];                                         \
            while (node->_children[0])                                         \
                node = node->_children[0];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (p && (node == p->_children[1])) {                           \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _prev)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node->_children[0] && !node->_parent)                             \
            return;                                                            \
                                                                               \
        if (node->_children[0]) {                                              \
            node = node->_children[0];                                         \
                                                                               \
            while (node->_children[1])                                         \
                node = node->_children[1];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (node == p->_children[0]) {                                  \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    /* tree */                                                                 \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _insert)(tree(K_T, V_T) t, K_T key, V_T val) {    \
        tree_node(K_T, V_T) node;                                              \
        int made_new = 0;                                                      \
        int only_lefts = 1;                                                    \
                                                                               \
        if (!t->_root) {                                                       \
            node = t->_beg = t->_root =                                        \
                CAT2(tree_node(K_T, V_T), _make)(key, val);                    \
            made_new = 1;                                                      \
        } else {                                                               \
            struct _tree_node(K_T, V_T) head = {0}; /* False tree root */      \
            tree_node(K_T, V_T) g, h;               /* Grandparent & parent */ \
            tree_node(K_T, V_T) p, q;               /* Iterator & parent */    \
            int dir = 0, last = 0;                                             \
                                                                               \
            h = &head;                                                         \
            g = p = NULL;                                                      \
            q = h->_children[1] = t->_root;                                    \
                                                                               \
            /* Search down the tree for a place to insert */                   \
            for (;;) {                                                         \
                if (q == NULL) {                                               \
                    /* Insert node at the first null link. */                  \
                    p->_children[dir] = q =                                    \
                        CAT2(tree_node(K_T, V_T), _make)(key, val);            \
                    q->_parent = p;                                            \
                    made_new = 1;                                              \
                } else if (_TN_IS_RED(q->_children[0]) &&                      \
                           _TN_IS_RED(q->_children[1])) {                      \
                    /* Simple red violation: color flip */                     \
                    q->_red = 1;                                               \
                    q->_children[0]->_red = 0;                                 \
                    q->_children[1]->_red = 0;                                 \
                }                                                              \
                                                                               \
                if (_TN_IS_RED(q) && _TN_IS_RED(p)) {                          \
                    /* Hard red violation: rotations necessary */              \
                    int dir2 = h->_children[1] == g;                           \
                    if (q == p->_children[last]) {                             \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate)(g, !last);      \
                    } else {                                                   \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate2)(g, !last);     \
                    }                                                          \
                                                                               \
                    if (h->_children[dir2])                                    \
                        h->_children[dir2]->_parent = h;                       \
                }                                                              \
                                                                               \
                /* Stop working if we inserted a node. This */                 \
                /* check also disallows duplicates in the tree */              \
                if (key == q->_key) {                                          \
                    if (!made_new) {                                           \
                        q->_val = val;                                         \
                    }                                                          \
                    node = q;                                                  \
                    break;                                                     \
                }                                                              \
                                                                               \
                last = dir;                                                    \
                dir = q->_key < key;                                           \
                only_lefts &= !dir;                                            \
                                                                               \
                /* Move the helpers down */                                    \
                if (g != NULL) {                                               \
                    h = g;                                                     \
                }                                                              \
                                                                               \
                g = p, p = q;                                                  \
                q = q->_children[dir];                                         \
            }                                                                  \
                                                                               \
            /* Update the root (it may be different) */                        \
            t->_root = head._children[1];                                      \
            if (t->_root) {                                                    \
                t->_root->_parent = NULL;                                      \
            }                                                                  \
        }                                                                      \
                                                                               \
        t->_root->_red = 0;                                                    \
        if (made_new) {                                                        \
            t->_len += 1;                                                      \
            if (only_lefts) {                                                  \
                t->_beg = node;                                                \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline int CAT2(tree(K_T, V_T), _delete)(tree(K_T, V_T) t,          \
                                                    K_T key) {                 \
        if (t->_root == NULL)                                                  \
            return 0;                                                          \
                                                                               \
        if (t->_len == 1 && t->_root->_key == key) {                           \
            CAT2(tree_node(K_T, V_T), _free(t->_root));                        \
            t->_root = t->_beg = NULL;                                         \
            t->_len = 0;                                                       \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        struct _tree_node(K_T, V_T) head = {0}; /* False tree root */          \
        tree_node(K_T, V_T) q, p, g;            /* Helpers */                  \
        tree_node(K_T, V_T) f = NULL;           /* Found item */               \
        int dir = 1;                                                           \
                                                                               \
        /* Set up our helpers */                                               \
        q = &head;                                                             \
        g = p = NULL;                                                          \
        q->_children[1] = t->_root;                                            \
                                                                               \
        /* Search and push a red node down */                                  \
        /* to fix red violations as we go  */                                  \
        while (q->_children[dir] != NULL) {                                    \
            int last = dir;                                                    \
                                                                               \
            /* Move the helpers down */                                        \
            g = p, p = q;                                                      \
            q = q->_children[dir];                                             \
            dir = q->_key < key;                                               \
                                                                               \
            /* Save the node with matching value and keep */                   \
            /* going; we'll do removal tasks at the end */                     \
            if (q->_key == key) {                                              \
                f = q;                                                         \
            }                                                                  \
                                                                               \
            /* Push the red node down with rotations and color flips */        \
            if (!_TN_IS_RED(q) && !_TN_IS_RED(q->_children[dir])) {            \
                if (_TN_IS_RED(q->_children[!dir])) {                          \
                    p->_children[last] =                                       \
                        CAT2(tree_node(K_T, V_T), _rotate)(q, dir);            \
                    if (p->_children[last])                                    \
                        p->_children[last]->_parent = p;                       \
                    p = p->_children[last];                                    \
                /* } else if (!_TN_IS_RED(q->_children[!dir])) {            */ \
                } else {                                                       \
                    tree_node(K_T, V_T) s = p->_children[!last];               \
                    if (s) {                                                   \
                        if (!_TN_IS_RED(s->_children[!last]) &&                \
                            !_TN_IS_RED(s->_children[last])) {                 \
                                                                               \
                            /* Color flip */                                   \
                            p->_red = 0;                                       \
                            s->_red = 1;                                       \
                            q->_red = 1;                                       \
                        } else {                                               \
                            int dir2 = g->_children[1] == p;                   \
                            if (_TN_IS_RED(s->_children[last])) {              \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate2)(p, last);  \
                            } else if (_TN_IS_RED(s->_children[!last])) {      \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate)(p, last);   \
                            }                                                  \
                            if (g->_children[dir2])                            \
                                g->_children[dir2]->_parent = g;               \
                                                                               \
                            /* Ensure correct coloring */                      \
                            q->_red = g->_children[dir2]->_red = 1;            \
                            g->_children[dir2]->_children[0]->_red = 0;        \
                            g->_children[dir2]->_children[1]->_red = 0;        \
                        }                                                      \
                    }                                                          \
                }                                                              \
            }                                                                  \
        }                                                                      \
                                                                               \
        /* Replace and remove the saved node */                                \
        if (f) {                                                               \
            K_T tmp_k = f->_key;                                               \
            V_T tmp_v = f->_val;                                               \
            f->_key = q->_key;                                                 \
            f->_val = q->_val;                                                 \
            q->_key = tmp_k;                                                   \
            q->_val = tmp_v;                                                   \
                                                                               \
            p->_children[p->_children[1] == q] =                               \
                q->_children[q->_children[0] == NULL];                         \
            if (p->_children[p->_children[1] == q])                            \
                p->_children[p->_children[1] == q]->_parent = p;               \
                                                                               \
            if (q == t->_beg) {                                                \
                t->_beg = p;                                                   \
            }                                                                  \
                                                                               \
            CAT2(tree_node(K_T, V_T), _free)(q);                               \
                                                                               \
            q = NULL;                                                          \
        }                                                                      \
                                                                               \
        /* Update the root (it may be different) */                            \
        t->_root = head._children[1];                                          \
        t->_root->_parent = NULL;                                              \
                                                                               \
        /* Make the root black for simplified logic */                         \
        if (t->_root != NULL) {                                                \
            t->_root->_red = 0;                                                \
        }                                                                      \
                                                                               \
        if (f == NULL)                                                         \
            return 0;                                                          \
                                                                               \
        t->_len -= 1;                                                          \
                                                                               \
        return 1;                                                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _lookup)(tree(K_T, V_T) t, K_T key) {             \
        tree_node(K_T, V_T) node = t->_root;                                   \
        while (node) {                                                         \
            if (node->_key == key) {                                           \
                break;                                                         \
            } else {                                                           \
                node = node->_children[node->_key < key];                      \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _begin)(tree(K_T, V_T) t) {                       \
        return _TI_FROM_TN(K_T, V_T, t, t->_beg);                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _last)(tree(K_T, V_T) t) {                        \
        tree_node(K_T, V_T) node = t->_root;                                   \
                                                                               \
        while (node) {                                                         \
            if (!node->_children[1])                                           \
                break;                                                         \
            node = node->_children[1];                                         \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree(K_T, V_T), _free)(tree(K_T, V_T) t) {         \
        if (t->_root)                                                          \
            CAT2(tree_node(K_T, V_T), _free)(t->_root);                        \
        TREE_FREE_FN(t);                                                       \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _geq)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if (!(node->_key < key)) {                                         \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _gtr)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if (key < node->_key) {                                            \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree(K_T, V_T) CAT2(tree(K_T, V_T), _make)(void) {           \
        tree(K_T, V_T) t =                                                     \
            (tree(K_T, V_T))TREE_MALLOC_FN(sizeof(struct _tree(K_T, V_T)));    \
                                                                               \
        struct _tree(K_T, V_T)                                                 \
            init = {._root = NULL,                                             \
                    ._beg = NULL,                                              \
                    ._len = 0,                                                 \
                    ._free = CAT2(tree(K_T, V_T), _free),                      \
                    ._lookup = CAT2(tree(K_T, V_T), _lookup),                  \
                    ._insert = CAT2(tree(K_T, V_T), _insert),                  \
                    ._delete = CAT2(tree(K_T, V_T), _delete),                  \
                    ._begin = CAT2(tree(K_T, V_T), _begin),                    \
                    ._last = CAT2(tree(K_T, V_T), _last),                      \
                    ._geq = CAT2(tree(K_T, V_T), _geq),                        \
                    ._gtr = CAT2(tree(K_T, V_T), _gtr)};                       \
                                                                               \
        *t = init;                                                             \
                                                                               \
        return t;                                                              \
    }

#define use_tree_c(K_T, V_T, CMP)                                              \
    typedef struct _tree_node(K_T, V_T) {                                      \
        int _red;                                                              \
        struct _tree_node(K_T, V_T) * _children[2], *_parent;                  \
        K_T _key;                                                              \
        V_T _val;                                                              \
    }                                                                          \
    *tree_node(K_T, V_T);                                                      \
                                                                               \
    struct _tree_it(K_T, V_T);                                                 \
                                                                               \
    typedef void (*CAT2(tree_it(K_T, V_T), _next_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
    typedef void (*CAT2(tree_it(K_T, V_T), _prev_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
                                                                               \
    struct _tree(K_T, V_T);                                                    \
                                                                               \
    typedef struct _tree_it(K_T, V_T) {                                        \
        struct _tree(K_T, V_T) * _t;                                           \
        tree_node(K_T, V_T) _node;                                             \
        CAT2(tree_it(K_T, V_T), _next_t)                                       \
        _next;                                                                 \
        CAT2(tree_it(K_T, V_T), _prev_t)                                       \
        _prev;                                                                 \
    }                                                                          \
    tree_it(K_T, V_T);                                                         \
                                                                               \
    typedef void (*CAT2(tree(K_T, V_T), _free_t))(struct _tree(K_T, V_T) *);   \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _lookup_t))(              \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _insert_t))(              \
        struct _tree(K_T, V_T) *, K_T, V_T);                                   \
    typedef int (*CAT2(tree(K_T, V_T), _delete_t))(struct _tree(K_T, V_T) *,   \
                                                   K_T);                       \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _begin_t))(               \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _last_t))(                \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _geq_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _gtr_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
                                                                               \
    typedef struct _tree(K_T, V_T) {                                           \
        tree_node(K_T, V_T) _root, _beg;                                       \
        uint64_t _len;                                                         \
                                                                               \
        CAT2(tree(K_T, V_T), _free_t) _free;                                   \
        CAT2(tree(K_T, V_T), _lookup_t) _lookup;                               \
        CAT2(tree(K_T, V_T), _insert_t) _insert;                               \
        CAT2(tree(K_T, V_T), _delete_t) _delete;                               \
        CAT2(tree(K_T, V_T), _begin_t) _begin;                                 \
        CAT2(tree(K_T, V_T), _last_t) _last;                                   \
        CAT2(tree(K_T, V_T), _geq_t) _geq;                                     \
        CAT2(tree(K_T, V_T), _geq_t) _gtr;                                     \
    }                                                                          \
    *tree(K_T, V_T);                                                           \
                                                                               \
    /* tree node */                                                            \
    static inline tree_node(K_T, V_T)                                          \
        CAT2(tree_node(K_T, V_T), _make)(K_T key, V_T val) {                   \
        tree_node(K_T, V_T) node =                                             \
            (tree_node(K_T, V_T))                                              \
                TREE_MALLOC_FN(sizeof(struct _tree_node(K_T, V_T)));           \
                                                                               \
        node->_red = 1;                                                        \
        node->_children[0] = node->_children[1] = node->_parent = NULL;        \
        node->_key = key;                                                      \
        node->_val = val;                                                      \
                                                                               \
        return node;                                                           \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_node(K_T, V_T),                               \
                            _free)(tree_node(K_T, V_T) node) {                 \
        if (node) {                                                            \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[0]);              \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[1]);              \
            TREE_FREE_FN(node);                                                \
        }                                                                      \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate)(      \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            result = node->_children[!dir];                                    \
            node->_children[!dir] = result->_children[dir];                    \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result->_children[dir] = node;                                     \
            if (result->_children[dir])                                        \
                result->_children[dir]->_parent = result;                      \
            node->_red = 1;                                                    \
            result->_red = 0;                                                  \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate2)(     \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            node->_children[!dir] = CAT2(tree_node(K_T, V_T), _rotate)(        \
                node->_children[!dir], !dir);                                  \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result = CAT2(tree_node(K_T, V_T), _rotate)(node, dir);            \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    /* tree it */                                                              \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _next)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node)                                                             \
            return;                                                            \
                                                                               \
        if (node->_children[1]) {                                              \
            node = node->_children[1];                                         \
            while (node->_children[0])                                         \
                node = node->_children[0];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (p && (node == p->_children[1])) {                           \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _prev)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node->_children[0] && !node->_parent)                             \
            return;                                                            \
                                                                               \
        if (node->_children[0]) {                                              \
            node = node->_children[0];                                         \
                                                                               \
            while (node->_children[1])                                         \
                node = node->_children[1];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (node == p->_children[0]) {                                  \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    /* tree */                                                                 \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _insert)(tree(K_T, V_T) t, K_T key, V_T val) {    \
        tree_node(K_T, V_T) node;                                              \
        int made_new = 0;                                                      \
        int only_lefts = 1;                                                    \
                                                                               \
        if (!t->_root) {                                                       \
            node = t->_beg = t->_root =                                        \
                CAT2(tree_node(K_T, V_T), _make)(key, val);                    \
            made_new = 1;                                                      \
        } else {                                                               \
            struct _tree_node(K_T, V_T) head = {0}; /* False tree root */      \
            tree_node(K_T, V_T) g, h;               /* Grandparent & parent */ \
            tree_node(K_T, V_T) p, q;               /* Iterator & parent */    \
            int dir = 0, last = 0;                                             \
                                                                               \
            h = &head;                                                         \
            g = p = NULL;                                                      \
            q = h->_children[1] = t->_root;                                    \
                                                                               \
            /* Search down the tree for a place to insert */                   \
            for (;;) {                                                         \
                if (q == NULL) {                                               \
                    /* Insert node at the first null link. */                  \
                    p->_children[dir] = q =                                    \
                        CAT2(tree_node(K_T, V_T), _make)(key, val);            \
                    q->_parent = p;                                            \
                    made_new = 1;                                              \
                } else if (_TN_IS_RED(q->_children[0]) &&                      \
                           _TN_IS_RED(q->_children[1])) {                      \
                    /* Simple red violation: color flip */                     \
                    q->_red = 1;                                               \
                    q->_children[0]->_red = 0;                                 \
                    q->_children[1]->_red = 0;                                 \
                }                                                              \
                                                                               \
                if (_TN_IS_RED(q) && _TN_IS_RED(p)) {                          \
                    /* Hard red violation: rotations necessary */              \
                    int dir2 = h->_children[1] == g;                           \
                    if (q == p->_children[last]) {                             \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate)(g, !last);      \
                    } else {                                                   \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate2)(g, !last);     \
                    }                                                          \
                                                                               \
                    if (h->_children[dir2])                                    \
                        h->_children[dir2]->_parent = h;                       \
                }                                                              \
                                                                               \
                /* Stop working if we inserted a node. This */                 \
                /* check also disallows duplicates in the tree */              \
                if ((CMP)(key, q->_key) == 0) {                                \
                    if (!made_new) {                                           \
                        q->_val = val;                                         \
                    }                                                          \
                    node = q;                                                  \
                    break;                                                     \
                }                                                              \
                                                                               \
                last = dir;                                                    \
                dir = (CMP)(q->_key, key) < 0;                                 \
                only_lefts &= !dir;                                            \
                                                                               \
                /* Move the helpers down */                                    \
                if (g != NULL) {                                               \
                    h = g;                                                     \
                }                                                              \
                                                                               \
                g = p, p = q;                                                  \
                q = q->_children[dir];                                         \
            }                                                                  \
                                                                               \
            /* Update the root (it may be different) */                        \
            t->_root = head._children[1];                                      \
            if (t->_root) {                                                    \
                t->_root->_parent = NULL;                                      \
            }                                                                  \
        }                                                                      \
                                                                               \
        t->_root->_red = 0;                                                    \
        if (made_new) {                                                        \
            t->_len += 1;                                                      \
            if (only_lefts) {                                                  \
                t->_beg = node;                                                \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline int CAT2(tree(K_T, V_T), _delete)(tree(K_T, V_T) t,          \
                                                    K_T key) {                 \
        if (t->_root == NULL)                                                  \
            return 0;                                                          \
                                                                               \
        if (t->_len == 1 && (CMP)(t->_root->_key, key) == 0) {                 \
            CAT2(tree_node(K_T, V_T), _free(t->_root));                        \
            t->_root = t->_beg = NULL;                                         \
            t->_len = 0;                                                       \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        struct _tree_node(K_T, V_T) head = {0}; /* False tree root */          \
        tree_node(K_T, V_T) q, p, g;            /* Helpers */                  \
        tree_node(K_T, V_T) f = NULL;           /* Found item */               \
        int dir = 1;                                                           \
                                                                               \
        /* Set up our helpers */                                               \
        q = &head;                                                             \
        g = p = NULL;                                                          \
        q->_children[1] = t->_root;                                            \
                                                                               \
        /* Search and push a red node down */                                  \
        /* to fix red violations as we go  */                                  \
        while (q->_children[dir] != NULL) {                                    \
            int last = dir;                                                    \
                                                                               \
            /* Move the helpers down */                                        \
            g = p, p = q;                                                      \
            q = q->_children[dir];                                             \
            dir = (CMP)(q->_key, key) < 0;                                     \
                                                                               \
            /* Save the node with matching value and keep */                   \
            /* going; we'll do removal tasks at the end */                     \
            if ((CMP)(q->_key, key) == 0) {                                    \
                f = q;                                                         \
            }                                                                  \
                                                                               \
            /* Push the red node down with rotations and color flips */        \
            if (!_TN_IS_RED(q) && !_TN_IS_RED(q->_children[dir])) {            \
                if (_TN_IS_RED(q->_children[!dir])) {                          \
                    p->_children[last] =                                       \
                        CAT2(tree_node(K_T, V_T), _rotate)(q, dir);            \
                    if (p->_children[last])                                    \
                        p->_children[last]->_parent = p;                       \
                    p = p->_children[last];                                    \
                /* } else if (!_TN_IS_RED(q->_children[!dir])) {            */ \
                } else {                                                       \
                    tree_node(K_T, V_T) s = p->_children[!last];               \
                    if (s) {                                                   \
                        if (!_TN_IS_RED(s->_children[!last]) &&                \
                            !_TN_IS_RED(s->_children[last])) {                 \
                                                                               \
                            /* Color flip */                                   \
                            p->_red = 0;                                       \
                            s->_red = 1;                                       \
                            q->_red = 1;                                       \
                        } else {                                               \
                            int dir2 = g->_children[1] == p;                   \
                            if (_TN_IS_RED(s->_children[last])) {              \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate2)(p, last);  \
                            } else if (_TN_IS_RED(s->_children[!last])) {      \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate)(p, last);   \
                            }                                                  \
                            if (g->_children[dir2])                            \
                                g->_children[dir2]->_parent = g;               \
                                                                               \
                            /* Ensure correct coloring */                      \
                            q->_red = g->_children[dir2]->_red = 1;            \
                            g->_children[dir2]->_children[0]->_red = 0;        \
                            g->_children[dir2]->_children[1]->_red = 0;        \
                        }                                                      \
                    }                                                          \
                }                                                              \
            }                                                                  \
        }                                                                      \
                                                                               \
        /* Replace and remove the saved node */                                \
        if (f) {                                                               \
            K_T tmp_k = f->_key;                                               \
            V_T tmp_v = f->_val;                                               \
            f->_key = q->_key;                                                 \
            f->_val = q->_val;                                                 \
            q->_key = tmp_k;                                                   \
            q->_val = tmp_v;                                                   \
                                                                               \
            p->_children[p->_children[1] == q] =                               \
                q->_children[q->_children[0] == NULL];                         \
            if (p->_children[p->_children[1] == q])                            \
                p->_children[p->_children[1] == q]->_parent = p;               \
                                                                               \
            if (q == t->_beg) {                                                \
                t->_beg = p;                                                   \
            }                                                                  \
                                                                               \
            CAT2(tree_node(K_T, V_T), _free)(q);                               \
                                                                               \
            q = NULL;                                                          \
        }                                                                      \
                                                                               \
        /* Update the root (it may be different) */                            \
        t->_root = head._children[1];                                          \
        t->_root->_parent = NULL;                                              \
                                                                               \
        /* Make the root black for simplified logic */                         \
        if (t->_root != NULL) {                                                \
            t->_root->_red = 0;                                                \
        }                                                                      \
                                                                               \
        if (f == NULL)                                                         \
            return 0;                                                          \
                                                                               \
        t->_len -= 1;                                                          \
                                                                               \
        return 1;                                                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _lookup)(tree(K_T, V_T) t, K_T key) {             \
        tree_node(K_T, V_T) node = t->_root;                                   \
        while (node) {                                                         \
            if ((CMP)(node->_key, key) == 0) {                                 \
                break;                                                         \
            } else {                                                           \
                node = node->_children[(CMP)(node->_key, key) < 0];            \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _begin)(tree(K_T, V_T) t) {                       \
        return _TI_FROM_TN(K_T, V_T, t, t->_beg);                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _last)(tree(K_T, V_T) t) {                        \
        tree_node(K_T, V_T) node = t->_root;                                   \
                                                                               \
        while (node) {                                                         \
            if (!node->_children[1])                                           \
                break;                                                         \
            node = node->_children[1];                                         \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree(K_T, V_T), _free)(tree(K_T, V_T) t) {         \
        if (t->_root)                                                          \
            CAT2(tree_node(K_T, V_T), _free)(t->_root);                        \
        TREE_FREE_FN(t);                                                       \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _geq)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if (!((CMP)(node->_key, key) < 0)) {                               \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _gtr)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if ((CMP)(key, node->_key) < 0) {                                  \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree(K_T, V_T) CAT2(tree(K_T, V_T), _make)(void) {           \
        tree(K_T, V_T) t =                                                     \
            (tree(K_T, V_T))TREE_MALLOC_FN(sizeof(struct _tree(K_T, V_T)));    \
                                                                               \
        struct _tree(K_T, V_T)                                                 \
            init = {._root = NULL,                                             \
                    ._beg = NULL,                                              \
                    ._len = 0,                                                 \
                    ._free = CAT2(tree(K_T, V_T), _free),                      \
                    ._lookup = CAT2(tree(K_T, V_T), _lookup),                  \
                    ._insert = CAT2(tree(K_T, V_T), _insert),                  \
                    ._delete = CAT2(tree(K_T, V_T), _delete),                  \
                    ._begin = CAT2(tree(K_T, V_T), _begin),                    \
                    ._last = CAT2(tree(K_T, V_T), _last),                      \
                    ._geq = CAT2(tree(K_T, V_T), _geq),                        \
                    ._gtr = CAT2(tree(K_T, V_T), _gtr)};                       \
                                                                               \
        *t = init;                                                             \
                                                                               \
        return t;                                                              \
    }

#define use_tree_ptr_c(K_T, V_T, CMP)                                          \
    typedef struct _tree_node(K_T, V_T) {                                      \
        int _red;                                                              \
        struct _tree_node(K_T, V_T) * _children[2], *_parent;                  \
        K_T _key;                                                              \
        V_T _val;                                                              \
    }                                                                          \
    *tree_node(K_T, V_T);                                                      \
                                                                               \
    struct _tree_it(K_T, V_T);                                                 \
                                                                               \
    typedef void (*CAT2(tree_it(K_T, V_T), _next_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
    typedef void (*CAT2(tree_it(K_T, V_T), _prev_t))(                          \
        struct _tree_it(K_T, V_T) * it);                                       \
                                                                               \
    struct _tree(K_T, V_T);                                                    \
                                                                               \
    typedef struct _tree_it(K_T, V_T) {                                        \
        struct _tree(K_T, V_T) * _t;                                           \
        tree_node(K_T, V_T) _node;                                             \
        CAT2(tree_it(K_T, V_T), _next_t)                                       \
        _next;                                                                 \
        CAT2(tree_it(K_T, V_T), _prev_t)                                       \
        _prev;                                                                 \
    }                                                                          \
    tree_it(K_T, V_T);                                                         \
                                                                               \
    typedef void (*CAT2(tree(K_T, V_T), _free_t))(struct _tree(K_T, V_T) *);   \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _lookup_t))(              \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _insert_t))(              \
        struct _tree(K_T, V_T) *, K_T, V_T);                                   \
    typedef int (*CAT2(tree(K_T, V_T), _delete_t))(struct _tree(K_T, V_T) *,   \
                                                   K_T);                       \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _begin_t))(               \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _last_t))(                \
        struct _tree(K_T, V_T) *);                                             \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _geq_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
    typedef tree_it(K_T, V_T) (*CAT2(tree(K_T, V_T), _gtr_t))(                 \
        struct _tree(K_T, V_T) *, K_T);                                        \
                                                                               \
    typedef struct _tree(K_T, V_T) {                                           \
        tree_node(K_T, V_T) _root, _beg;                                       \
        uint64_t _len;                                                         \
                                                                               \
        CAT2(tree(K_T, V_T), _free_t)  _free;                                  \
        CAT2(tree(K_T, V_T), _lookup_t)  _lookup;                              \
        CAT2(tree(K_T, V_T), _insert_t)  _insert;                              \
        CAT2(tree(K_T, V_T), _delete_t)  _delete;                              \
        CAT2(tree(K_T, V_T), _begin_t)  _begin;                                \
        CAT2(tree(K_T, V_T), _last_t)  _last;                                  \
        CAT2(tree(K_T, V_T), _geq_t)  _geq;                                    \
        CAT2(tree(K_T, V_T), _geq_t)  _gtr;                                    \
    }                                                                          \
    *tree(K_T, V_T);                                                           \
                                                                               \
    /* tree node */                                                            \
    static inline tree_node(K_T, V_T)                                          \
        CAT2(tree_node(K_T, V_T), _make)(K_T key, V_T val) {                   \
        tree_node(K_T, V_T) node =                                             \
            (tree_node(K_T, V_T))                                              \
                TREE_MALLOC_FN(sizeof(struct _tree_node(K_T, V_T)));           \
                                                                               \
        node->_red = 1;                                                        \
        node->_children[0] = node->_children[1] = node->_parent = NULL;        \
        node->_key = key;                                                      \
        node->_val = val;                                                      \
                                                                               \
        return node;                                                           \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_node(K_T, V_T),                               \
                            _free)(tree_node(K_T, V_T) node) {                 \
        if (node) {                                                            \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[0]);              \
            CAT2(tree_node(K_T, V_T), _free)(node->_children[1]);              \
            TREE_FREE_FN(node);                                                \
        }                                                                      \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate)(      \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            result = node->_children[!dir];                                    \
            node->_children[!dir] = result->_children[dir];                    \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result->_children[dir] = node;                                     \
            if (result->_children[dir])                                        \
                result->_children[dir]->_parent = result;                      \
            node->_red = 1;                                                    \
            result->_red = 0;                                                  \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    static inline tree_node(K_T, V_T) CAT2(tree_node(K_T, V_T), _rotate2)(     \
        tree_node(K_T, V_T) node, int dir) {                                   \
        tree_node(K_T, V_T) result = NULL;                                     \
        if (node) {                                                            \
            node->_children[!dir] = CAT2(tree_node(K_T, V_T), _rotate)(        \
                node->_children[!dir], !dir);                                  \
            if (node->_children[!dir])                                         \
                node->_children[!dir]->_parent = node;                         \
            result = CAT2(tree_node(K_T, V_T), _rotate)(node, dir);            \
        }                                                                      \
        return result;                                                         \
    }                                                                          \
                                                                               \
    /* tree it */                                                              \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _next)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node)                                                             \
            return;                                                            \
                                                                               \
        if (node->_children[1]) {                                              \
            node = node->_children[1];                                         \
            while (node->_children[0])                                         \
                node = node->_children[0];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (p && (node == p->_children[1])) {                           \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree_it(K_T, V_T),                                 \
                            _prev)(struct _tree_it(K_T, V_T) * it) {           \
        tree_node(K_T, V_T) node = it->_node;                                  \
                                                                               \
        if (!node->_children[0] && !node->_parent)                             \
            return;                                                            \
                                                                               \
        if (node->_children[0]) {                                              \
            node = node->_children[0];                                         \
                                                                               \
            while (node->_children[1])                                         \
                node = node->_children[1];                                     \
        } else {                                                               \
            tree_node(K_T, V_T) p = node->_parent;                             \
            while (node == p->_children[0]) {                                  \
                node = p;                                                      \
                p = p->_parent;                                                \
            }                                                                  \
            node = p;                                                          \
        }                                                                      \
                                                                               \
        it->_node = node;                                                      \
    }                                                                          \
                                                                               \
    /* tree */                                                                 \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _insert)(tree(K_T, V_T) t, K_T key, V_T val) {    \
        tree_node(K_T, V_T) node;                                              \
        int made_new = 0;                                                      \
        int only_lefts = 1;                                                    \
                                                                               \
        if (!t->_root) {                                                       \
            node = t->_beg = t->_root =                                        \
                CAT2(tree_node(K_T, V_T), _make)(key, val);                    \
            made_new = 1;                                                      \
        } else {                                                               \
            struct _tree_node(K_T, V_T) head = {0}; /* False tree root */      \
            tree_node(K_T, V_T) g, h;               /* Grandparent & parent */ \
            tree_node(K_T, V_T) p, q;               /* Iterator & parent */    \
            int dir = 0, last = 0;                                             \
                                                                               \
            h = &head;                                                         \
            g = p = NULL;                                                      \
            q = h->_children[1] = t->_root;                                    \
                                                                               \
            /* Search down the tree for a place to insert */                   \
            for (;;) {                                                         \
                if (q == NULL) {                                               \
                    /* Insert node at the first null link. */                  \
                    p->_children[dir] = q =                                    \
                        CAT2(tree_node(K_T, V_T), _make)(key, val);            \
                    q->_parent = p;                                            \
                    made_new = 1;                                              \
                } else if (_TN_IS_RED(q->_children[0]) &&                      \
                           _TN_IS_RED(q->_children[1])) {                      \
                    /* Simple red violation: color flip */                     \
                    q->_red = 1;                                               \
                    q->_children[0]->_red = 0;                                 \
                    q->_children[1]->_red = 0;                                 \
                }                                                              \
                                                                               \
                if (_TN_IS_RED(q) && _TN_IS_RED(p)) {                          \
                    /* Hard red violation: rotations necessary */              \
                    int dir2 = h->_children[1] == g;                           \
                    if (q == p->_children[last]) {                             \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate)(g, !last);      \
                    } else {                                                   \
                        h->_children[dir2] =                                   \
                            CAT2(tree_node(K_T, V_T), _rotate2)(g, !last);     \
                    }                                                          \
                                                                               \
                    if (h->_children[dir2])                                    \
                        h->_children[dir2]->_parent = h;                       \
                }                                                              \
                                                                               \
                /* Stop working if we inserted a node. This */                 \
                /* check also disallows duplicates in the tree */              \
                if ((CMP)(&key, &q->_key) == 0) {                              \
                    if (!made_new) {                                           \
                        q->_val = val;                                         \
                    }                                                          \
                    node = q;                                                  \
                    break;                                                     \
                }                                                              \
                                                                               \
                last = dir;                                                    \
                dir = (CMP)(&q->_key, &key) < 0;                               \
                only_lefts &= !dir;                                            \
                                                                               \
                /* Move the helpers down */                                    \
                if (g != NULL) {                                               \
                    h = g;                                                     \
                }                                                              \
                                                                               \
                g = p, p = q;                                                  \
                q = q->_children[dir];                                         \
            }                                                                  \
                                                                               \
            /* Update the root (it may be different) */                        \
            t->_root = head._children[1];                                      \
            if (t->_root) {                                                    \
                t->_root->_parent = NULL;                                      \
            }                                                                  \
        }                                                                      \
                                                                               \
        t->_root->_red = 0;                                                    \
        if (made_new) {                                                        \
            t->_len += 1;                                                      \
            if (only_lefts) {                                                  \
                t->_beg = node;                                                \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline int CAT2(tree(K_T, V_T), _delete)(tree(K_T, V_T) t,          \
                                                    K_T key) {                 \
        if (t->_root == NULL)                                                  \
            return 0;                                                          \
                                                                               \
        if (t->_len == 1 && (CMP)(&t->_root->_key, &key) == 0) {               \
            CAT2(tree_node(K_T, V_T), _free(t->_root));                        \
            t->_root = t->_beg = NULL;                                         \
            t->_len = 0;                                                       \
            return 1;                                                          \
        }                                                                      \
                                                                               \
        struct _tree_node(K_T, V_T) head = {0}; /* False tree root */          \
        tree_node(K_T, V_T) q, p, g;            /* Helpers */                  \
        tree_node(K_T, V_T) f = NULL;           /* Found item */               \
        int dir = 1;                                                           \
                                                                               \
        /* Set up our helpers */                                               \
        q = &head;                                                             \
        g = p = NULL;                                                          \
        q->_children[1] = t->_root;                                            \
                                                                               \
        /* Search and push a red node down */                                  \
        /* to fix red violations as we go  */                                  \
        while (q->_children[dir] != NULL) {                                    \
            int last = dir;                                                    \
                                                                               \
            /* Move the helpers down */                                        \
            g = p, p = q;                                                      \
            q = q->_children[dir];                                             \
            dir = (CMP)(&q->_key, &key) < 0;                                   \
                                                                               \
            /* Save the node with matching value and keep */                   \
            /* going; we'll do removal tasks at the end */                     \
            if ((CMP)(&q->_key, &key) == 0) {                                  \
                f = q;                                                         \
            }                                                                  \
                                                                               \
            /* Push the red node down with rotations and color flips */        \
            if (!_TN_IS_RED(q) && !_TN_IS_RED(q->_children[dir])) {            \
                if (_TN_IS_RED(q->_children[!dir])) {                          \
                    p->_children[last] =                                       \
                        CAT2(tree_node(K_T, V_T), _rotate)(q, dir);            \
                    if (p->_children[last])                                    \
                        p->_children[last]->_parent = p;                       \
                    p = p->_children[last];                                    \
                /* } else if (!_TN_IS_RED(q->_children[!dir])) {            */ \
                } else {                                                       \
                    tree_node(K_T, V_T) s = p->_children[!last];               \
                    if (s) {                                                   \
                        if (!_TN_IS_RED(s->_children[!last]) &&                \
                            !_TN_IS_RED(s->_children[last])) {                 \
                                                                               \
                            /* Color flip */                                   \
                            p->_red = 0;                                       \
                            s->_red = 1;                                       \
                            q->_red = 1;                                       \
                        } else {                                               \
                            int dir2 = g->_children[1] == p;                   \
                            if (_TN_IS_RED(s->_children[last])) {              \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate2)(p, last);  \
                            } else if (_TN_IS_RED(s->_children[!last])) {      \
                                g->_children[dir2] = CAT2(tree_node(K_T, V_T), \
                                                          _rotate)(p, last);   \
                            }                                                  \
                            if (g->_children[dir2])                            \
                                g->_children[dir2]->_parent = g;               \
                                                                               \
                            /* Ensure correct coloring */                      \
                            q->_red = g->_children[dir2]->_red = 1;            \
                            g->_children[dir2]->_children[0]->_red = 0;        \
                            g->_children[dir2]->_children[1]->_red = 0;        \
                        }                                                      \
                    }                                                          \
                }                                                              \
            }                                                                  \
        }                                                                      \
                                                                               \
        /* Replace and remove the saved node */                                \
        if (f) {                                                               \
            K_T tmp_k = f->_key;                                               \
            V_T tmp_v = f->_val;                                               \
            f->_key = q->_key;                                                 \
            f->_val = q->_val;                                                 \
            q->_key = tmp_k;                                                   \
            q->_val = tmp_v;                                                   \
                                                                               \
            p->_children[p->_children[1] == q] =                               \
                q->_children[q->_children[0] == NULL];                         \
            if (p->_children[p->_children[1] == q])                            \
                p->_children[p->_children[1] == q]->_parent = p;               \
                                                                               \
            if (q == t->_beg) {                                                \
                t->_beg = p;                                                   \
            }                                                                  \
                                                                               \
            CAT2(tree_node(K_T, V_T), _free)(q);                               \
                                                                               \
            q = NULL;                                                          \
        }                                                                      \
                                                                               \
        /* Update the root (it may be different) */                            \
        t->_root = head._children[1];                                          \
        t->_root->_parent = NULL;                                              \
                                                                               \
        /* Make the root black for simplified logic */                         \
        if (t->_root != NULL) {                                                \
            t->_root->_red = 0;                                                \
        }                                                                      \
                                                                               \
        if (f == NULL)                                                         \
            return 0;                                                          \
                                                                               \
        t->_len -= 1;                                                          \
                                                                               \
        return 1;                                                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _lookup)(tree(K_T, V_T) t, K_T key) {             \
        tree_node(K_T, V_T) node = t->_root;                                   \
        while (node) {                                                         \
            if ((CMP)(&node->_key, &key) == 0) {                               \
                break;                                                         \
            } else {                                                           \
                node = node->_children[(CMP)(&node->_key, &key) < 0];          \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _begin)(tree(K_T, V_T) t) {                       \
        return _TI_FROM_TN(K_T, V_T, t, t->_beg);                              \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _last)(tree(K_T, V_T) t) {                        \
        tree_node(K_T, V_T) node = t->_root;                                   \
                                                                               \
        while (node) {                                                         \
            if (!node->_children[1])                                           \
                break;                                                         \
            node = node->_children[1];                                         \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, node);                                 \
    }                                                                          \
                                                                               \
    static inline void CAT2(tree(K_T, V_T), _free)(tree(K_T, V_T) t) {         \
        if (t->_root)                                                          \
            CAT2(tree_node(K_T, V_T), _free)(t->_root);                        \
        TREE_FREE_FN(t);                                                       \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _geq)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if (!((CMP)(&node->_key, &key) < 0)) {                             \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree_it(K_T, V_T)                                            \
        CAT2(tree(K_T, V_T), _gtr)(tree(K_T, V_T) t, K_T key) {                \
        tree_node(K_T, V_T) last = NULL, node = t->_root;                      \
                                                                               \
        while (node) {                                                         \
            if ((CMP)(&key, &node->_key) < 0) {                                \
                last = node;                                                   \
                node = node->_children[0];                                     \
            } else {                                                           \
                node = node->_children[1];                                     \
            }                                                                  \
        }                                                                      \
                                                                               \
        return _TI_FROM_TN(K_T, V_T, t, last);                                 \
    }                                                                          \
                                                                               \
    static inline tree(K_T, V_T) CAT2(tree(K_T, V_T), _make)(void) {           \
        tree(K_T, V_T) t =                                                     \
            (tree(K_T, V_T))TREE_MALLOC_FN(sizeof(struct _tree(K_T, V_T)));    \
                                                                               \
        struct _tree(K_T, V_T)                                                 \
            init = {._root = NULL,                                             \
                    ._beg = NULL,                                              \
                    ._len = 0,                                                 \
                    ._free = CAT2(tree(K_T, V_T), _free),                      \
                    ._lookup = CAT2(tree(K_T, V_T), _lookup),                  \
                    ._insert = CAT2(tree(K_T, V_T), _insert),                  \
                    ._delete = CAT2(tree(K_T, V_T), _delete),                  \
                    ._begin = CAT2(tree(K_T, V_T), _begin),                    \
                    ._last = CAT2(tree(K_T, V_T), _last),                      \
                    ._geq = CAT2(tree(K_T, V_T), _geq),                        \
                    ._gtr = CAT2(tree(K_T, V_T), _gtr)};                       \
                                                                               \
        *t = init;                                                             \
                                                                               \
        return t;                                                              \
    }

#endif
