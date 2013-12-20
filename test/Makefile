protocol_send.o: protocol_send.c ../*.c ../crypt/*.c
	gcc -o protocol_send.o -I../ -I../crypt/ protocol_send.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c

protocol_decrypt.o: protocol_decrypt.c ../*.c ../crypt/*.c
	gcc -o protocol_decrypt.o -I../ -I../crypt/ protocol_decrypt.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c
	
gen_dec.o: gen_dec.c ../*.c ../crypt/*.c
	gcc -o gen_dec.o -I../ -I../crypt/ gen_dec.c ../protocol.c ../buffer.c ../crypt/*.c ../udp.c ../json.c

%.dec: %.json gen_dec.o
	cp -f $*.json test.json
	./gen_dec.o
	cp -f test.dec $*.dec

clean:
	-rm -f *.o
