CXX=g++
CFLAGS=-g -Wno-write-strings

RELEASE_DIR=release
LIB_DIR=lib
OBJECTS=main.o crypto/utils.o
HEADERS=-I./libs -L./libs 
LIBS=-pthread -lssl -lcrypto -ldl 

default: libsslgen.so libsslgen.a $(OBJECTS)
		cp crypto/*.h $(RELEASE_DIR)/
		$(CXX) $(HEADERS) -I./release -L$(RELEASE_DIR) $(CFLAGS) -o $(RELEASE_DIR)/main $(OBJECTS) -lsslgen $(LIBS) 

%.o: %.cpp
		$(CXX) $(HEADERS) -c  $< $(CFLAGS) -o $@ $(LIBS)

libsslgen.so: crypto/sslgen.cpp
		mkdir -p $(RELEASE_DIR)
		mkdir -p $(LIB_DIR)
		$(CXX) $(HEADERS) $(CFLAGS) -c crypto/sslgen.cpp -o crypto/sslgen.o  $(LIBS)
		$(CXX) $(HEADERS) $(CFLAGS) -shared  -Wl,-soname,libsslgen.so -o $(LIB_DIR)/libsslgen.so crypto/sslgen.o $(LIBS)

libsslgen.a: crypto/sslgen.cpp
		ar rcs $(RELEASE_DIR)/libsslgen.a crypto/sslgen.o

clean: 
		rm -rf *.o
		rm -rf crypto/*.o
		rm -rf ./$(RELEASE_DIR)/
		rm -rf ./$(LIB_DIR)/