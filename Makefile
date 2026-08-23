CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include
LDFLAGS = -lX11 -lXext -lssl -lcrypto
TARGET = fileguard
SRC = fileguard.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
