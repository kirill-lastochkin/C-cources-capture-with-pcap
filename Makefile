OBJ = main.o clb.o
FLAGS = -lpcap
out : $(OBJ)
	cc -o out $(OBJ) $(FLAGS)
main.o : service.h
clb.o : service.h
clean :
	-rm out $(OBJ)

