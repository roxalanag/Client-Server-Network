# Build a client and server using only the student's my_storage.cc

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing persist concurrenthashmap_factories \
                  crypto err file net my_pool my_crypto my_quota_tracker \
                  my_functable my_mru helpers

# Names for building shared objects
SO_CXX    = all_keys odd_key_vals invalid1 invalid2 broken1 broken2
SO_COMMON = 

# NB: This Makefile does not add extra CXXFLAGS

# Pull in the common build rules
include common.mk
    