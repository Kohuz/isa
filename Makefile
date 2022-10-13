CC		 = g++
CPPLAGS	 = -Wall
LDFLAGS	 = -lpcap
OBJFILES = export.o flow.o packet.o
TARGET	 = flow

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CPPLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -r $(OBJILES) $(TARGET)
