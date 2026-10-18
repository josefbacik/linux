# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -O2 -g $(KHDR_INCLUDES)

TEST_GEN_PROGS := cell_life_test cell_spawn_test cell_slots_test cell_ids_test
TEST_GEN_PROGS += cell_boundary_test cell_net_test
TEST_GEN_FILES := cell_child

include ../lib.mk

# Runs inside a cell, whose tree holds nothing else.
$(OUTPUT)/cell_child: cell_child.c cell_util.h
	$(CC) $(CFLAGS) -static -o $@ $<

$(TEST_GEN_PROGS): cell_test.h cell_util.h
