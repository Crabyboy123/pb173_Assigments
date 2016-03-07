CC := g++
CFLAGS := -g -Wall -Wextra -std=c++11

SRCDIR := src
BUILDDIR := build
TARGET := bin/encrypt
 
SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
SOURCES_TEST=test/testing.cpp
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
LIB := -L lib/mbedtls-2.2.1/library -lmbedcrypto -lmbedtls -lmbedx509 
INC := -I include -I lib/mbedtls-2.2.1/include/mbedtls

$(TARGET): $(OBJECTS) 
	$(CC) $^ -o $(TARGET) $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	rm -r $(BUILDDIR) $(TARGET)

tests:
	@mkdir -p $(BUILDDIR)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/encryption.cpp $(SOURCES_TEST) $(INC) $(LIB) -o tests

run-tests: tests
	./bin/tests

