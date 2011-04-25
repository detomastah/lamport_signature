all:
	gcc -lssl sign.c -o sign
	gcc -lssl verify.c -o verify
