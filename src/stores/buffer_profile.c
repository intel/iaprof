#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "iaprof.h"
#include "buffer_profile.h"

/**
  Global array of GEMs that we've seen.
  This is what we'll search through when we get an
  EU stall sample.
**/
pthread_rwlock_t buffer_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
struct buffer_profile *buffer_profile_arr = NULL;
struct interval_profile *interval_profile_arr = NULL;
size_t buffer_profile_size = 0, buffer_profile_used = 0;
uint64_t iba = 0;

void clear_interval_profiles()
{
        memset(interval_profile_arr, 0,
               buffer_profile_size * sizeof(struct interval_profile));
}

/* Ensure that we have enough room to place a newly-seen sample, and place it.
   Does NOT grab the lock, so the caller should. */
uint64_t grow_buffer_profiles()
{
	size_t old_size;

	/* Ensure there's enough room in the array */
	if (buffer_profile_size == buffer_profile_used) {
		/* Not enough room in the array */
		old_size = buffer_profile_size;
		buffer_profile_size += 64;
		buffer_profile_arr = realloc(
			buffer_profile_arr,
			buffer_profile_size * sizeof(struct buffer_profile));
		interval_profile_arr = realloc(
			interval_profile_arr,
			buffer_profile_size * sizeof(struct interval_profile));
		memset(buffer_profile_arr + buffer_profile_used, 0,
		       (buffer_profile_size - old_size) *
			       sizeof(struct buffer_profile));
		memset(interval_profile_arr + buffer_profile_used, 0,
		       (buffer_profile_size - old_size) *
			       sizeof(struct interval_profile));
		if (debug)
			fprintf(stderr, "INFO: Increasing buffer size.\n");
	}

	buffer_profile_used++;
	return buffer_profile_used - 1;
}

/* Looks up a buffer in the buffer_profile_arr by handle/vm_id pair. */
int get_buffer_binding(uint32_t handle, uint32_t vm_id)
{
        int n;
        struct buffer_profile *gem;
        
        for (n = 0; n < buffer_profile_used; n++) {
                gem = &buffer_profile_arr[n];
                if ((gem->handle == handle) &&
                    (gem->vm_id == vm_id)) {
                        return n;
                }
        }
        
        return -1;
}

/* Looks up a buffer in the buffer_profile_arr by file/handle pair
   Returns -1 if not found. */
int get_buffer_profile(uint64_t file, uint32_t handle)
{
	int n;
	struct buffer_profile *gem;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		if ((gem->handle == handle) &&
		    (gem->file == file)) {
			return n;
		}
	}

	return -1;
}

/* Looks up a buffer in the buffer_profile_arr by file/handle pair
   (using its mapping_info, or mmap call).
   Returns -1 if not found. */
int get_buffer_profile_by_mapping(uint64_t file, uint32_t handle)
{
	int n;
	struct buffer_profile *gem;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		if ((gem->mapping_info.handle == handle) &&
		    (gem->mapping_info.file == file)) {
			return n;
		}
	}

	return -1;
}

/* Looks up a buffer in the buffer_profile_arr by the file/handle pair
   found in its vm_bind_info (or vm_bind call).
   Returns -1 if not found. */
int get_buffer_profile_by_binding(uint64_t file, uint32_t handle)
{
	int n;
	struct buffer_profile *gem;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		if ((gem->vm_bind_info.handle == handle) &&
		    (gem->vm_bind_info.file == file)) {
			return n;
		}
	}

	return -1;
}

/* Looks up a buffer in the buffer_profile_arr by its GPU address. */
int get_buffer_profile_by_gpu_addr(uint64_t gpu_addr)
{
	int n;
	struct buffer_profile *gem;

	for (n = 0; n < buffer_profile_used; n++) {
		gem = &buffer_profile_arr[n];
		if (gem->vm_bind_info.gpu_addr == gpu_addr) {
			return n;
		}
	}

	return -1;
}
