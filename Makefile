CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

TARGET = rsa_encryption
SRCS = main.cpp src/rsa_encryption.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

main.o: main.cpp include/rsa_encryption.h
	$(CXX) $(CXXFLAGS) -c main.cpp

src/rsa_encryption.o: src/rsa_encryption.cpp include/rsa_encryption.h
	$(CXX) $(CXXFLAGS) -c src/rsa_encryption.cpp -o src/rsa_encryption.o

clean:
	rm -f $(OBJS) $(TARGET)
