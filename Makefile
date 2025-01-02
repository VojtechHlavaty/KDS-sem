# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lssl -lcrypto -lz

# Directories
SRC_DIR = .
OBJ_DIR = ./obj
BIN_DIR = ./bin

# Source files
SENDER_SRC = $(SRC_DIR)/sender.c
RECEIVER_SRC = $(SRC_DIR)/receiver.c

# Executable names
SENDER_EXEC = sender
RECEIVER_EXEC = $(BIN_DIR)/receiver

# Default target
all: $(SENDER_EXEC) $(RECEIVER_EXEC)

# Create output directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build sender
$(SENDER_EXEC): $(SENDER_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Build receiver
$(RECEIVER_EXEC): $(RECEIVER_SRC) $(RECEIVER_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(RECEIVER_SRC) $(LIBS)

# Build receiver object file
$(RECEIVER_OBJ): $(RECEIVER_SRC) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build files
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) sender

.PHONY: all clean