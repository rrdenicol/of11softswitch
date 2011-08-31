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

#include "flex-array.h"
#include <stdlib.h>
#include <string.h>

void
flex_array_init(struct flex_array *f){

    f->size = 0;
    f->total = 0;
}

void
flex_array_put(struct flex_array *f, const void *p, size_t size){

    memcpy(&f->entries[f->size],p,size);
    f->size += size;
}

/* Returns the byte following the last byte allocated for use (but not
 * necessarily in use) by 'b'. */
void *
flex_array_tail(const struct flex_array *f) 
{
    return (uint8_t *) f->entries + f->size;
}

void 
flex_array_put_zeros(struct flex_array *f, size_t size){

     memset(f->entries, 0, size);
     f->size += size;
}

