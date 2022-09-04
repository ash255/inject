objects = test_target.o

test_target : $(objects)
	cc -o test_target $(objects) -lpthread 
test_target.o : test_target.c
	cc -c test_target.c
	
.PHONY : clean
clean :
	-rm test_target $(objects)
