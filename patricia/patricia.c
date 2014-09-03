/*
 * $Id: patricia.c,v 1.7 2005/12/07 20:46:41 dplonka Exp $
 * Dave Plonka <plonka@doit.wisc.edu>
 *
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors. 
 *
 * This file had been called "radix.c" in the MRT sources.
 *
 * I renamed it to "patricia.c" since it's not an implementation of a general
 * radix trie.  Also I pulled in various requirements from "prefix.c" and
 * "demo.c" so that it could be used as a standalone API.
 *
 *
 *	Bunch of mods from David Meyer (dmm613@gmail.com) to make 
 *	this deal with IPv6 in a more friendly fashion
 *
 *
 */

/*
 * 2014/8/4
 * modified by upa@haeena.net
 * this version can be compiled for kernel use.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ctype.h> /* isdigit */
#include <linux/errno.h> /* errno */
#include <linux/printk.h>
#include <stddef.h> /* NULL */
#include <linux/string.h> /* memcpy, strchr, strlen */
#include <linux/types.h> /* BSD: for inet_addr */
#include <linux/socket.h> /* BSD, Linux: for inet_addr */
#include <uapi/linux/in.h> /* BSD, Linux: for inet_addr */
#include <uapi/linux/in6.h> /* BSD, Linux: for inet_addr */


#include "patricia.h"

/* #include <assert.h> assert */
#define assert(expr)							\
	do {								\
		if (!(expr)) {						\
			printk (KERN_ERR "patricia assert %s:%d\n",	\
				__func__, __LINE__);			\
		}							\
	} while (0)							\



#define Delete kfree

/* { from prefix.c */

/* prefix_tochar
 * convert prefix information to bytes
 */
u_char *prefix_tochar (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);
    return ((u_char *) & prefix->add.sin);
}

int comp_with_mask (void *addr, void *dest, u_int mask)
{

    if ( /* mask/8 == 0 || */ memcmp (addr, dest, mask / 8) == 0) {
	int n = mask / 8;
	int m = ((-1) << (8 - (mask % 8)));

	if (mask % 8 == 0 || (((u_char *)addr)[n] & m) == (((u_char *)dest)[n] & m))
	    return (1);
    }
    return (0);
}


#define PATRICIA_MAX_THREADS		16

prefix_t *New_Prefix2 (int family, void *dest, int bitlen, prefix_t *prefix)
{
    int dynamic_allocated = 0;
    int default_bitlen    = 0;

    if (prefix == NULL) {
	/*	prefix = calloc(1, sizeof (prefix_t)); */
	if ((prefix = (prefix_t *)kmalloc(sizeof(prefix_t), GFP_KERNEL)) == NULL) {
	    printk (KERN_ERR "New_Prefix2: can't allocate new prefix");
	    return(0);
	}
	memset(prefix, 0, sizeof (prefix_t));
	dynamic_allocated++;
    }


    switch(family) {
    case AF_INET:
        default_bitlen = sizeof(struct in_addr) * 8;
	memcpy (&prefix->add.sin, dest, sizeof(struct in_addr));
        break;
    case AF_INET6:
        default_bitlen = sizeof(struct in6_addr) * 8;
	memcpy (&prefix->add.sin6, dest, sizeof(struct in6_addr));
	break;
    default:
	kfree(prefix);
        return (NULL);
    }

    prefix->bitlen = (bitlen >= 0)? bitlen: default_bitlen;
    prefix->family = family;
    prefix->ref_count = 0;
    if (dynamic_allocated) {
        prefix->ref_count++;
    }
    return (prefix);
}

prefix_t *New_Prefix (int family, void *dest, int bitlen)
{
    return (New_Prefix2 (family, dest, bitlen, NULL));
}


prefix_t *Ref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);
    if (prefix->ref_count == 0) {
	/* make a copy in case of a static prefix */
        return (New_Prefix2 (prefix->family, &prefix->add, prefix->bitlen, NULL));
    }
    prefix->ref_count++;
    /* fprintf(stderr, "[A %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    return (prefix);
}

void Deref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return;
    /* for secure programming, raise an assert. no static prefix can call this */
    assert (prefix->ref_count > 0);

    prefix->ref_count--;
    assert (prefix->ref_count >= 0);
    if (prefix->ref_count <= 0) {
	Delete (prefix);
	return;
    }
}

/* } */

/* #define PATRICIA_DEBUG 1  */

static int num_active_patricia = 0;

/* these routines support continuous mask only */

patricia_tree_t *
New_Patricia (int maxbits)
{
    patricia_tree_t *patricia = kmalloc(sizeof *patricia, GFP_KERNEL);
    memset (patricia, 0, sizeof *patricia);

    patricia->maxbits = maxbits;
    patricia->head = NULL;
    patricia->num_active_node = 0;
    assert (maxbits <= PATRICIA_MAXBITS); /* XXX */
    num_active_patricia++;
    return (patricia);
}


/*
 * if func is supplied, it will be called as func(node->data)
 * before deleting the node
 */

void
Clear_Patricia (patricia_tree_t *patricia, void_fn_t func)
{

    if (patricia->head) {

        patricia_node_t *Xstack[PATRICIA_MAXBITS+1];
        patricia_node_t **Xsp = Xstack;
        patricia_node_t *Xrn = patricia->head;

        while (Xrn) {
            patricia_node_t *l = Xrn->l;
            patricia_node_t *r = Xrn->r;

    	    if (Xrn->prefix) {
		Deref_Prefix (Xrn->prefix);
		if (Xrn->data && func)
	    	    func (Xrn->data);
    	    }
    	    Delete (Xrn);
	    patricia->num_active_node--;

            if (l) {
                if (r) {
                    *Xsp++ = r;
                }
                Xrn = l;
            } else if (r) {
                Xrn = r;
            } else if (Xsp != Xstack) {
                Xrn = *(--Xsp);
            } else {
                Xrn = NULL;
            }
        }
    }

    // assert (patricia->num_active_node == 0);
    /* Delete (patricia); */
}


void
Destroy_Patricia (patricia_tree_t *patricia, void_fn_t func)
{
    Clear_Patricia (patricia, func);
    Delete (patricia);
    num_active_patricia--;
}


/*
 * if func is supplied, it will be called as func(node->prefix, node->data)
 */

void
patricia_process (patricia_tree_t *patricia, void_fn_walk_t func)
{
    patricia_node_t *node;
    assert (func);

    PATRICIA_WALK (patricia->head, node) {
	func (node->prefix, node->data);
    } PATRICIA_WALK_END;
}

void
patricia_process2 (patricia_tree_t *patricia, void_fn_walk2_t func,
		   void * user1, void * user2)
{
    patricia_node_t *node;
    assert (func);

    PATRICIA_WALK (patricia->head, node) {
	    func (node->prefix, node->data, user1, user2);
    } PATRICIA_WALK_END;
}

size_t
patricia_walk_inorder(patricia_node_t *node, void_fn_walk_t func)
{
    size_t n = 0;
    assert(func);

    if (node->l) {
         n += patricia_walk_inorder(node->l, func);
    }

    if (node->prefix) {
	func(node->prefix, node->data);
	n++;
    }
	
    if (node->r) {
         n += patricia_walk_inorder(node->r, func);
    }

    return n;
}


patricia_node_t *
patricia_search_exact (patricia_tree_t *patricia, prefix_t *prefix)
{
    patricia_node_t *node;
    u_char *addr;
    u_int bitlen;
    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);;
    if (patricia->head == NULL)
	return (NULL);

    node = patricia->head;
    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

	if (BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_exact: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_exact: take right at %u\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_exact: take left %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_exact: take left at %u\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	if (node == NULL)
	    return (NULL);
    }

#ifdef PATRICIA_DEBUG
    if (node->prefix)
        fprintf (stderr, "patricia_search_exact: stop at %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
    else
        fprintf (stderr, "patricia_search_exact: stop at %u\n", node->bit);
#endif /* PATRICIA_DEBUG */
    if (node->bit > bitlen || node->prefix == NULL)
	return (NULL);
    assert (node->bit == bitlen);
    assert (node->bit == node->prefix->bitlen);
    if (comp_with_mask (prefix_tochar (node->prefix), prefix_tochar (prefix),
			bitlen)) {
#ifdef PATRICIA_DEBUG
        fprintf (stderr, "patricia_search_exact: found %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	return (node);
    }
    return (NULL);
}


/* if inclusive != 0, "best" may be the given prefix itself */
patricia_node_t *
patricia_search_best2 (patricia_tree_t *patricia, prefix_t *prefix, int inclusive)
{
    patricia_node_t *node;
    patricia_node_t *stack[PATRICIA_MAXBITS + 1];
    u_char *addr;
    u_int bitlen;
    int cnt = 0;

    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL)
	return (NULL);

    node = patricia->head;
    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;

    while (node->bit < bitlen) {

	if (node->prefix) {
#ifdef PATRICIA_DEBUG
            fprintf (stderr, "patricia_search_best: push %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    stack[cnt++] = node;
	}

	if (BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_best: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_best: take right at %u\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_search_best: take left %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_search_best: take left at %u\n", 
			 node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	if (node == NULL)
	    break;
    }

    if (inclusive && node && node->prefix)
	stack[cnt++] = node;

#ifdef PATRICIA_DEBUG
    if (node == NULL)
        fprintf (stderr, "patricia_search_best: stop at null\n");
    else if (node->prefix)
        fprintf (stderr, "patricia_search_best: stop at %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
    else
        fprintf (stderr, "patricia_search_best: stop at %u\n", node->bit);
#endif /* PATRICIA_DEBUG */

    if (cnt <= 0)
	return (NULL);

    while (--cnt >= 0) {
	node = stack[cnt];
#ifdef PATRICIA_DEBUG
        fprintf (stderr, "patricia_search_best: pop %s/%d\n", 
	         prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	if (comp_with_mask (prefix_tochar (node->prefix), 
			    prefix_tochar (prefix),
			    node->prefix->bitlen) && node->prefix->bitlen <= bitlen) {
#ifdef PATRICIA_DEBUG
            fprintf (stderr, "patricia_search_best: found %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    return (node);
	}
    }
    return (NULL);
}


patricia_node_t *
patricia_search_best (patricia_tree_t *patricia, prefix_t *prefix)
{
    return (patricia_search_best2 (patricia, prefix, 1));
}


patricia_node_t *
patricia_lookup (patricia_tree_t *patricia, prefix_t *prefix)
{
    patricia_node_t *node, *new_node, *parent, *glue;
    u_char *addr, *test_addr;
    u_int bitlen, check_bit, differ_bit;
    int i, j, r;

    assert (patricia);
    assert (prefix);
    assert (prefix->bitlen <= patricia->maxbits);

    if (patricia->head == NULL) {
	node = kmalloc(sizeof *node, GFP_KERNEL);
	memset (node, 0, sizeof *node);
	node->bit = prefix->bitlen;
	node->prefix = Ref_Prefix (prefix);
	node->parent = NULL;
	node->l = node->r = NULL;
	node->data = NULL;
	patricia->head = node;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #0 %s/%d (head)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	patricia->num_active_node++;
	return (node);
    }

    addr = prefix_touchar (prefix);
    bitlen = prefix->bitlen;
    node = patricia->head;

    while (node->bit < bitlen || node->prefix == NULL) {

	if (node->bit < patricia->maxbits &&
	    BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	    if (node->r == NULL)
		break;
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_lookup: take right %s/%d\n", 
	                 prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_lookup: take right at %u\n", node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->r;
	}
	else {
	    if (node->l == NULL)
		break;
#ifdef PATRICIA_DEBUG
	    if (node->prefix)
    	        fprintf (stderr, "patricia_lookup: take left %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
	    else
    	        fprintf (stderr, "patricia_lookup: take left at %u\n", node->bit);
#endif /* PATRICIA_DEBUG */
	    node = node->l;
	}

	assert (node);
    }

    assert (node->prefix);
#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_lookup: stop at %s/%d\n", 
	     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */

    test_addr = prefix_touchar (node->prefix);
    /* find the first bit different */
    check_bit = (node->bit < bitlen)? node->bit: bitlen;
    differ_bit = 0;
    for (i = 0; i*8 < check_bit; i++) {
	if ((r = (addr[i] ^ test_addr[i])) == 0) {
	    differ_bit = (i + 1) * 8;
	    continue;
	}
	/* I know the better way, but for now */
	for (j = 0; j < 8; j++) {
	    if (BIT_TEST (r, (0x80 >> j)))
		break;
	}
	/* must be found */
	assert (j < 8);
	differ_bit = i * 8 + j;
	break;
    }
    if (differ_bit > check_bit)
	differ_bit = check_bit;
#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_lookup: differ_bit %d\n", differ_bit);
#endif /* PATRICIA_DEBUG */

    parent = node->parent;
    while (parent && parent->bit >= differ_bit) {
	node = parent;
	parent = node->parent;
#ifdef PATRICIA_DEBUG
	if (node->prefix)
            fprintf (stderr, "patricia_lookup: up to %s/%d\n", 
	             prefix_toa (node->prefix), node->prefix->bitlen);
	else
            fprintf (stderr, "patricia_lookup: up to %u\n", node->bit);
#endif /* PATRICIA_DEBUG */
    }

    if (differ_bit == bitlen && node->bit == bitlen) {
	if (node->prefix) {
#ifdef PATRICIA_DEBUG 
    	    fprintf (stderr, "patricia_lookup: found %s/%d\n", 
		     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	    return (node);
	}
	node->prefix = Ref_Prefix (prefix);
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new node #1 %s/%d (glue mod)\n",
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	assert (node->data == NULL);
	return (node);
    }

    new_node = kmalloc(sizeof *new_node, GFP_KERNEL);
    memset (new_node, 0, sizeof *new_node);
    new_node->bit = prefix->bitlen;
    new_node->prefix = Ref_Prefix (prefix);
    new_node->parent = NULL;
    new_node->l = new_node->r = NULL;
    new_node->data = NULL;
    patricia->num_active_node++;

    if (node->bit == differ_bit) {
	new_node->parent = node;
	if (node->bit < patricia->maxbits &&
	    BIT_TEST (addr[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
	    assert (node->r == NULL);
	    node->r = new_node;
	}
	else {
	    assert (node->l == NULL);
	    node->l = new_node;
	}
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #2 %s/%d (child)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	return (new_node);
    }

    if (bitlen == differ_bit) {
	if (bitlen < patricia->maxbits &&
	    BIT_TEST (test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07))) {
	    new_node->r = node;
	}
	else {
	    new_node->l = node;
	}
	new_node->parent = node->parent;
	if (node->parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = new_node;
	}
	else if (node->parent->r == node) {
	    node->parent->r = new_node;
	}
	else {
	    node->parent->l = new_node;
	}
	node->parent = new_node;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #3 %s/%d (parent)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    }
    else {
        glue = kmalloc(sizeof *glue, GFP_KERNEL);
	memset (glue, 0, sizeof * glue);
        glue->bit = differ_bit;
        glue->prefix = NULL;
        glue->parent = node->parent;
        glue->data = NULL;
        patricia->num_active_node++;
	if (differ_bit < patricia->maxbits &&
	    BIT_TEST (addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07))) {
	    glue->r = new_node;
	    glue->l = node;
	}
	else {
	    glue->r = node;
	    glue->l = new_node;
	}
	new_node->parent = glue;

	if (node->parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = glue;
	}
	else if (node->parent->r == node) {
	    node->parent->r = glue;
	}
	else {
	    node->parent->l = glue;
	}
	node->parent = glue;
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_lookup: new_node #4 %s/%d (glue+node)\n", 
		 prefix_toa (prefix), prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    }
    return (new_node);
}


void
patricia_remove (patricia_tree_t *patricia, patricia_node_t *node)
{
    patricia_node_t *parent, *child;

    assert (patricia);
    assert (node);

    if (node->r && node->l) {
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_remove: #0 %s/%d (r & l)\n", 
		 prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	
	/* this might be a placeholder node -- have to check and make sure
	 * there is a prefix aossciated with it ! */
	if (node->prefix != NULL) 
	  Deref_Prefix (node->prefix);
	node->prefix = NULL;
	/* Also I needed to clear data pointer -- masaki */
	node->data = NULL;
	return;
    }

    if (node->r == NULL && node->l == NULL) {
#ifdef PATRICIA_DEBUG
	fprintf (stderr, "patricia_remove: #1 %s/%d (!r & !l)\n", 
		 prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
	parent = node->parent;
	Deref_Prefix (node->prefix);
	Delete (node);
        patricia->num_active_node--;

	if (parent == NULL) {
	    assert (patricia->head == node);
	    patricia->head = NULL;
	    return;
	}

	if (parent->r == node) {
	    parent->r = NULL;
	    child = parent->l;
	}
	else {
	    assert (parent->l == node);
	    parent->l = NULL;
	    child = parent->r;
	}

	if (parent->prefix)
	    return;

	/* we need to remove parent too */

	if (parent->parent == NULL) {
	    assert (patricia->head == parent);
	    patricia->head = child;
	}
	else if (parent->parent->r == parent) {
	    parent->parent->r = child;
	}
	else {
	    assert (parent->parent->l == parent);
	    parent->parent->l = child;
	}
	child->parent = parent->parent;
	Delete (parent);
        patricia->num_active_node--;
	return;
    }

#ifdef PATRICIA_DEBUG
    fprintf (stderr, "patricia_remove: #2 %s/%d (r ^ l)\n", 
	     prefix_toa (node->prefix), node->prefix->bitlen);
#endif /* PATRICIA_DEBUG */
    if (node->r) {
	child = node->r;
    }
    else {
	assert (node->l);
	child = node->l;
    }
    parent = node->parent;
    child->parent = parent;

    Deref_Prefix (node->prefix);
    Delete (node);
    patricia->num_active_node--;

    if (parent == NULL) {
	assert (patricia->head == node);
	patricia->head = child;
	return;
    }

    if (parent->r == node) {
	parent->r = child;
    }
    else {
        assert (parent->l == node);
	parent->l = child;
    }
}




/* } */
