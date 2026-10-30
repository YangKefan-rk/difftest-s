CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
RVWMO := ../../../rvwmo
ADAPTER := ..
SOURCE_FILES := $(ADAPTER)/event_emitter.cpp $(RVWMO)/stream.cpp atomic_emitter_test.cpp

.PHONY: all test clean

all: atomic_emitter_test

atomic_emitter_test: $(SOURCE_FILES)
	$(CXX) $(CXXFLAGS) -I$(RVWMO) -I$(ADAPTER) $^ -o $@

test: atomic_emitter_test
	./atomic_emitter_test

clean:
	rm -f atomic_emitter_test
