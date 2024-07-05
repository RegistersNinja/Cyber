#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"
#include "cache.h"

/**
 * Allocate a cache entry
 */
struct cache_entry *alloc_entry(char *path, char *content_type, void *content, int content_length)
{
    ///////////////////
    struct cache_entry *new_entry = malloc(sizeof(struct cache_entry));
    
    int size = strlen(path) + 1;
    new_entry->path = calloc(1, size);
    new_entry->path = strncpy(new_entry->path, path, size);

    size = sizeof(*content_type) * strlen(content_type) + 1;
    new_entry->content_type = calloc(1, size);
    new_entry->content_type = strncpy(new_entry->content_type, content_type, size);

    new_entry->content_length = content_length;

    // Copy content into entry
    size = content_length;
    new_entry->content = calloc(1, size);
    new_entry->content = memcpy(new_entry->content, content, size);

    return new_entry;
    ///////////////////
}

/**
 * Deallocate a cache entry
 */
void free_entry(struct cache_entry *entry)
{
    ///////////////////
    free(entry->path);
    free(entry->content_type);
    free(entry->content);
    free(entry);
    ///////////////////
}

/**
 * Insert a cache entry at the head of the linked list
 */
void dllist_insert_head(struct cache *cache, struct cache_entry *ce)
{
    // Insert at the head of the list
    if (cache->head == NULL) {
        cache->head = cache->tail = ce;
        ce->prev = ce->next = NULL;
    } else {
        cache->head->prev = ce;
        ce->next = cache->head;
        ce->prev = NULL;
        cache->head = ce;
    }
}

/**
 * Move a cache entry to the head of the list
 */
void dllist_move_to_head(struct cache *cache, struct cache_entry *ce)
{
    if (ce != cache->head) {
        if (ce == cache->tail) {
            // We're the tail
            cache->tail = ce->prev;
            cache->tail->next = NULL;

        } else {
            // We're neither the head nor the tail
            ce->prev->next = ce->next;
            ce->next->prev = ce->prev;
        }

        ce->next = cache->head;
        cache->head->prev = ce;
        ce->prev = NULL;
        cache->head = ce;
    }
}


/**
 * Removes the tail from the list and returns it
 * 
 * NOTE: does not deallocate the tail
 */
struct cache_entry *dllist_remove_tail(struct cache *cache)
{
    struct cache_entry *oldtail = cache->tail;

    cache->tail = oldtail->prev;
    cache->tail->next = NULL;

    cache->cur_size--;

    return oldtail;
}

/**
 * Create a new cache
 * 
 * max_size: maximum number of entries in the cache
 * hashsize: hashtable size (0 for default)
 */
struct cache *cache_create(int max_size, int hashsize)
{
    ///////////////////
    struct cache* cache = malloc(sizeof(struct cache));
    cache->head = NULL;
    cache->tail = NULL;
    cache->cur_size = 0;
    cache->max_size = max_size;
    cache->index = hashtable_create(hashsize, NULL);

    return cache;
    ///////////////////
}

void cache_free(struct cache *cache)
{
    struct cache_entry *cur_entry = cache->head;

    hashtable_destroy(cache->index);

    while (cur_entry != NULL) {
        struct cache_entry *next_entry = cur_entry->next;

        free_entry(cur_entry);

        cur_entry = next_entry;
    }

    free(cache);
}

/**
 * Store an entry in the cache
 *
 * This will also remove the least-recently-used items as necessary.
 * 
 * NOTE: doesn't check for duplicate cache entries
 */
void cache_put(struct cache *cache, char *path, char *content_type, void *content, int content_length)
{
    ///////////////////
    struct cache_entry* new_entry = alloc_entry(path, content_type, content,
                                                content_length);
    dllist_insert_head(cache, new_entry);                                            
    hashtable_put(cache->index,new_entry->path,new_entry);
    if (cache->cur_size >= cache->max_size)
    {
        hashtable_delete(cache->index,cache->tail->path);
        free_entry(dllist_remove_tail(cache));
    }
    
    cache->cur_size +=1;
    ///////////////////
}

/**
 * Retrieve an entry from the cache
 */
struct cache_entry *cache_get(struct cache *cache, char *path)
{
    ///////////////////
    struct cache_entry* is_found = hashtable_get(cache->index,path);
    if(is_found == NULL)
        return NULL;
    else 
    {
        //If we found the head already
        if(is_found == cache->head)
            return cache->head;
        //If we found the tail
        if(is_found->next == NULL)
            {
                is_found->next = cache->head;
                cache->head->prev = is_found;
                (is_found->prev)->next = NULL;
                cache->tail = is_found->prev;
                is_found->prev = NULL;
                cache->head = is_found;
                return cache->head;
            }
        //If it's in the middle
        (is_found->prev)->next = is_found->next;
        (is_found->next)->prev = is_found->prev;
        is_found->next = cache->head;
        is_found->prev = NULL;
        (cache->head)->prev = is_found;
        cache->head = is_found;

        return cache->head;
    }
    ///////////////////
}