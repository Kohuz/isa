CC		 = g++
CXXFLAGS = -Wall -g
LDFLAGS	 = -lpcap
OBJFILES = export.o flow.o packet.o
TARGET	 = flow

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CXXFLAGS) -o  $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -r $(OBJFILES) $(TARGET)
