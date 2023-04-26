SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
ASAN_OPTIONS = detect_stack_use_after_return=1

.PHONY: clean

%.o: %.c
	gcc $< -o valgrind_$(@)
	gcc -fsanitize=address -O1 -g $< -o asan_$(@)
	chmod +x valgrind_$(@)
	chmod +x asan_$(@)
	valgrind ./valgrind_$(@) || true
	ASAN_OPTIONS=$(ASAN_OPTIONS) ./asan_$(@) || true

all: $(OBJS)

clean:
	rm *.o 2> /dev/null || true
