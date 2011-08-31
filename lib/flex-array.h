/*
 * Copyright (c) 2011 CPqD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FLEX_ARRAY_H
#define FLEX_ARRAY_H 1

#include <stdlib.h>
#include <stdint.h>

/*A flexible array structure */
struct flex_array {

   uint16_t size;  /* Array size */
   uint16_t total; /* Number of entries */
   uint8_t pad[4];  /* Allign to 64 bits */
   uint8_t entries[]; /* */
         
};

void
flex_array_init(struct flex_array *f);

void
flex_array_put(struct flex_array *f, const void *p, size_t size);

void
flex_array_put_zeros(struct flex_array *f, size_t size);
 
#endif /* flex-array.h */
