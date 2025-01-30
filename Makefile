all: shellpeek

shellpeek: shellpeek.c
	$(CC) -g -O0 -Wall -Wextra -pedantic -D_GNU_SOURCE $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -f shellpeek

.PHONY: clean
