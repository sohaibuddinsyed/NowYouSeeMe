CC = gcc

CFLAGS  = -lssl -lcrypto

# the build target executable:
TARGET = ufsend ufrec

all: $(TARGET)
 
# executables
$(TARGET): ufsend.c ufrec
	$(CC) ufsend.c $(CFLAGS) -o ufsend 
	$(CC) ufrec.c $(CFLAGS) -o ufrec


clean:
	$(RM) $(TARGET)