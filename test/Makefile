CC = gcc
CFLAGS = 
INCLUDE = -I. -I../ -I../crypt/

protocol_send.o: protocol_send.c ../*.c ../crypt/*.c
	$(CC) -o $*.o $(INCLUDE) $*.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c

protocol_encrypt.o: protocol_encrypt.c ../*.c ../crypt/*.c
	$(CC) -o $*.o $(INCLUDE) $*.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c testhelper.c

protocol_decrypt.o: protocol_decrypt.c ../*.c ../crypt/*.c
	$(CC) -o $*.o $(INCLUDE) $*.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c
	
gen_dec.o: gen_dec.c ../*.c ../crypt/*.c
	$(CC) -o $*.o $(INCLUDE) $*.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c

%.dec: %.json gen_dec.o
	cp -f $*.json test.json
	./gen_dec.o
	cp -f test.dec $*.dec
%.send: %.dec
	socat pipe:$*.dec udp-sendto:0.0.0.0:8889
	
listen:
	socat udp-listen:8888 stdout
clean:
	-rm -f *.o *.dec
