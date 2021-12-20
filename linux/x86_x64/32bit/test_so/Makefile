objects = test_so.o

test_so : $(objects)
	cc -o test_so.so $(objects) -shared
test_so.o : test_so.c
	cc -c test_so.c
	
.PHONY : clean
clean :
	-rm test_so.so $(objects)