rwildcard = $(foreach d, $(wildcard $1*), $(filter $(subst *, %, $2), $d) $(call rwildcard, $d/, $2))

CXX	= g++
LD	= ld

name := kelftool

dir_source := src
dir_build := build

CXXFLAGS = --std=c++17
LDLIBS = -lcrypto

# next flags only for macos
# change paths to your location of openssl@1.1
OUTPUT_OPTION += -I/Users/user/usr/local/Cellar/openssl@1.1/1.1.1m/include
LDLIBS += -L/Users/user/usr/local/Cellar/openssl@1.1/1.1.1m/lib
# OUTPUT_OPTION += -I/usr/local/opt/openssl@1.1/include
# LDLIBS += -L/usr/local/opt/openssl@1.1/lib

objects =	$(patsubst $(dir_source)/%.cpp, $(dir_build)/%.o, \
			$(call rwildcard, $(dir_source), *.cpp))

.PHONY: all
all: $(dir_build)/$(name)

.PHONY: clean
clean:
	@rm -rf $(dir_build)

$(dir_build)/$(name): $(objects)
	$(LINK.cc) $^ $(LDLIBS) $(OUTPUT_OPTION) -o $@

$(dir_build)/%.o: $(dir_source)/%.cpp
	@mkdir -p "$(@D)"
	$(COMPILE.cpp) $< $(OUTPUT_OPTION) -o $@
