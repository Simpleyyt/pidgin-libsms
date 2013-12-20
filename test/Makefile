protocol_send.o: protocol_send.c ../*.c ../crypt/*.c
	gcc -o protocol_send.o -I../ -I../crypt/ protocol_send.c ../protocol.c ../context.c ../crypt/*.c ../udp.c ../json.c

protocol_decrypt.o: protocol_decrypt.c ../*.c ../crypt/*.c
	gcc -o protocol_decrypt.o -I../ -I../crypt/ protocol_decrypt.c ../protocol.c ../context.c ../crypt/*.c ../udp.c ../json.c
	
clean:
	-rm -f *.o
