protocol_test.o: protocol_test.c ../*.c ../crypt/*.c
	gcc -o protocol_test.o -I../ -I../crypt/ protocol_test.c ../protocol.c ../context.c ../crypt/*.c ../udp.c ../json.c
clean:
	-rm -f *.o
