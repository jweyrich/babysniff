#include "types/pair.h"
#include <string.h>

pair_t *pair_array_first(const pair_array_t *array) {
    if (array == NULL)
        return NULL;
    return (pair_t *)&array->data[0];
}

pair_t *pair_array_last(const pair_array_t *array) {
    if (array == NULL)
        return NULL;
    return (pair_t *)&array->data[array->count-1];
}

pair_t *pair_array_lookup_key(const pair_array_t *array, int key) {
    if (array == NULL)
        return NULL;
    for (size_t i = 0; i < array->count; i++) {
        if (key == array->data[i].key)
            return (pair_t *)&array->data[i];
    }
    return NULL;
}

pair_t *pair_array_lookup_value(const pair_array_t *array, const char *value) {
    if (array == NULL)
        return NULL;
    for (size_t i = 0; i < array->count; i++) {
        if (strcmp(value, array->data[i].value) == 0)
            return (pair_t *)&array->data[i];
    }
    return NULL;
}
