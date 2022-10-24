CC=gcc
# -I.
CFLAGS=-ggdb3 -Wall -std=gnu99
LIBS=-pthread
DEPS =
_OBJ = main.o

OBJDIR=obj
OBJ=$(patsubst %,$(OBJDIR)/%,$(_OBJ))

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

hw0: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: all clean

all: hw0

clean:
	rm -f $(OBJDIR)/*.o *~ hw0
