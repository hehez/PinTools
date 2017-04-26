SRCS = loop.c branch.c fibonacci.c calculator.c array.c tree.c stringmerge.c fncptr.c

EXES=$(SRCS:.c=)

CC=gcc
CFLAGS=-g

all: $(EXES)

$(EXECS): % : %.c
	$(CC) $(CFLAGS) -o $@ $<
	

clean:
	rm -f $(OBJS) $(EXES) *.out
