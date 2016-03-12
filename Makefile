OBJ = main.o clb.o
FLAGS = -lpcap -pg
out : $(OBJ)
	cc -o out $(OBJ) $(FLAGS)
main.o : service.h
clb.o : service.h
clean :
	-rm out $(OBJ)
cm : 
	cc -o out main.c clb.c $(FLAGS)

