objects = inject.o ptrace.o

inject : $(objects)
	cc -o inject $(objects) -ldl  -m32
inject.o : inject.c ptrace.h
	cc -c inject.c -m32
ptrace.o : ptrace.h
	cc -c ptrace.c -m32

.PHONY : clean
clean :
	-rm inject $(objects)
