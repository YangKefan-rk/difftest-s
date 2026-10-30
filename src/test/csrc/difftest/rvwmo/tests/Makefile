CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
RVWMO := ..
SOURCES := checker checker_event_consumer dependency lrsc memory ppo order reference
RVWMO_SOURCES := $(addprefix $(RVWMO)/,$(addsuffix .cpp,$(SOURCES)))

.PHONY: all test clean

all: atomic_lifecycle_test

atomic_lifecycle_test: atomic_lifecycle_test.cpp $(RVWMO_SOURCES)
	$(CXX) $(CXXFLAGS) -I$(RVWMO) $^ -o $@

test: atomic_lifecycle_test
	./atomic_lifecycle_test

clean:
	rm -f atomic_lifecycle_test
