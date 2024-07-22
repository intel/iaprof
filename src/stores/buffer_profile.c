#include <pthread.h>
#include "buffer_profile.h"

/**
  Global array of GEMs that we've seen.
  This is what we'll search through when we get an
  EU stall sample.
**/
pthread_rwlock_t buffer_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
struct buffer_profile *buffer_profile_arr = NULL;
size_t buffer_profile_size = 0, buffer_profile_used = 0;
uint64_t iba = 0;
