TARGET    = key4cert
VERSION   = v0.1
REV       = $(shell git rev-parse --short HEAD || cat git-rev)

DEBUG     = -g
DEFINES   = -DK4C_VERSION=\"$(VERSION)\"

# If we somehow found a revision number
ifneq ($(REV),)
DEFINES  += -DK4C_REV=\"$(REV)\"
endif


CFLAGS    = -pipe -std=c99 -Wall -pedantic $(DEBUG) $(DEFINES)
SRC_FILES = $(wildcard *.m)
O_FILES   = $(SRC_FILES:%.c=%.o)
LIBS      = -framework Foundation -framework Security -framework CoreFoundation -lcrypto


.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(O_FILES)
	gcc $(O_FILES) -o $(TARGET) $(LIBS) $(CFLAGS)

clean:
	rm -f *.o $(TARGET)

run: $(TARGET)
	./$(TARGET)

install:
	@echo No yet implemented, just copy the file yourself.
