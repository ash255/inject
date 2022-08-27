objects = test_target.o

test_target : $(objects)
	cc -o test_target $(objects) -lpthread -m32
test_target.o : test_target.c
	cc -c test_target.c -m32
	
.PHONY : clean
clean :
	-rm test_target $(objects)
