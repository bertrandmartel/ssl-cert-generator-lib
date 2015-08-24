CXX=g++
CFLAGS=-Wno-write-strings

RELEASE_DIR=release
OBJECTS=main.o crypto/utils.o

default: libsslgen.so $(OBJECTS)
		$(CXX) $(CFLAGS) -o $(RELEASE_DIR)/main $(OBJECTS) -L$(RELEASE_DIR) -pthread -lssl -lcrypto -lsslgen 
		cp crypto/*.h $(RELEASE_DIR)/

%.o: %.cpp
		$(CXX) -c  $< $(CFLAGS) -o $@ -pthread -lssl -lcrypto -lsslgen 

libsslgen.so: crypto/sslgen.cpp
		mkdir -p $(RELEASE_DIR)
		$(CXX) $(CFLAGS) -fPIC -c crypto/sslgen.cpp -o crypto/sslgen.o
		$(CXX) $(CFLAGS) -shared  -Wl,-soname,libsslgen.so -o $(RELEASE_DIR)/libsslgen.so crypto/sslgen.o -pthread -lssl -lcrypto 

clean: 
		rm -rf *.o
		rm -rf crypto/*.o
		rm -rf ./$(RELEASE_DIR)/