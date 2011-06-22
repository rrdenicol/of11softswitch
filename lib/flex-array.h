#ifndef FLEX_ARRAY_H
#define FLEX_ARRAY_H 1

#include <stdint.h>

/*A flexible array structure */
struct flex_array {
       struct {
             uint32_t size;  /* Array size */
             uint32_t total; /* Number of entries */
             uint8_t entries[]; /* */
        };
          
};

#endif /* flex-array.h */
