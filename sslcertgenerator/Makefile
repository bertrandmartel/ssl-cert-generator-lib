CXX=g++
CFLAGS=-Wno-write-strings

RELEASE_DIR=release
LIB_DIR=lib
OBJECTS=main.o crypto/utils.o
LIBS=-pthread -lssl -lcrypto 

default: libsslgen.so libsslgen.a $(OBJECTS)
		$(CXX) $(CFLAGS) -o $(RELEASE_DIR)/main $(OBJECTS) -L$(RELEASE_DIR) -lsslgen $(LIBS)
		cp crypto/*.h $(RELEASE_DIR)/

%.o: %.cpp
		$(CXX) -c  $< $(CFLAGS) -o $@ $(LIBS) -lsslgen 

libsslgen.so: crypto/sslgen.cpp
		mkdir -p $(RELEASE_DIR)
		mkdir -p $(LIB_DIR)
		$(CXX) $(CFLAGS) -c crypto/sslgen.cpp -o crypto/sslgen.o  $(LIBS)
		$(CXX) $(CFLAGS) -shared  -Wl,-soname,libsslgen.so -o $(LIB_DIR)/libsslgen.so crypto/sslgen.o $(LIBS)

libsslgen.a: crypto/sslgen.cpp
		ar rcs $(RELEASE_DIR)/libsslgen.a crypto/sslgen.o

clean: 
		rm -rf *.o
		rm -rf crypto/*.o
		rm -rf ./$(RELEASE_DIR)/
		rm -rf ./$(LIB_DIR)/