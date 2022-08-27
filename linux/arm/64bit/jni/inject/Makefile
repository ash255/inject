objects = inject.o ptrace.o

inject : $(objects)
	cc -o inject $(objects) -ldl 
inject.o : inject.c ptrace.h
	cc -c inject.c
ptrace.o : ptrace.h
	cc -c ptrace.c

.PHONY : clean
clean :
	-rm inject $(objects)
