/*
 * =====================================================================
 * Copyright (c) 2016 PLUMgrid, http://plumgrid.com
 *
 * This source is subject to the PLUMgrid License.
 * All rights reserved.
 *
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * PLUMgrid confidential information, delete if you are not the
 * intended recipient.
 *
 * =====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/cmap.h"

typedef struct my_node {
  struct cmap_node cmap_node;
  int data;
} my_node;

int main(int argc, char **argv) {
  struct cmap cmap;
  struct my_node my_node;
  struct my_node my_node_2;
  struct my_node * iterator;
  struct cmap_node *cmap_node;
  uint32_t hash = 42;

  my_node.data = 24;
  my_node_2.data = 23;

  cmap_init(&cmap);
  cmap_insert(&cmap, &(my_node.cmap_node), hash);
  cmap_insert(&cmap, &(my_node_2.cmap_node), hash);

  CMAP_FOR_EACH_WITH_HASH(iterator, cmap_node, hash, &cmap) {
    printf("Node data: %d\n", iterator->data);
  }

  return 0;
}
