# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -O2 -g $(KHDR_INCLUDES)

TEST_GEN_PROGS := cell_test
TEST_GEN_FILES := cell_child

include ../lib.mk

# Runs inside a cell, whose tree holds nothing else.
$(OUTPUT)/cell_child: cell_child.c cell_util.h
	$(CC) $(CFLAGS) -static -o $@ $<

$(OUTPUT)/cell_test: cell_test.c cell_util.h
