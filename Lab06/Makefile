SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

.PHONY: clean

%.o: %.c
	gcc $< -o valgrind_$(@)
	gcc -fsanitize=address -O1 -g $< -o asan_$(@)
	chmod +x valgrind_$(@)
	chmod +x asan_$(@)
	valgrind ./valgrind_$(@)
	./asan_$(@) || true

all: $(OBJS)

clean:
	rm *.o 2> /dev/null || true
