CXX = g++
CXXFLAGS = -std=c++98 -Wall -Werror -pedantic
LDFLAGS = -lcrypto -lm

SOURCES = bignum.cpp rsa.cpp main.cpp
HEADERS = bignum.h rsa.h
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = rsa_program

.PHONY: all clean run rebuild

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

rebuild: clean all
