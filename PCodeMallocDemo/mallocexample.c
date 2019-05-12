#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>


int getNum(){
	return atoi("10");
}


int g = 7;

int oneOf3(){
	if(rand() > 1){
		return 1;
	}

	else if (rand() > 2){
		return 2;
	}
	return 3;
}

int getNumber(){
	int x = 6;
	if ( rand() < 9)
		return 9;
	else if (rand() < 100){
		return atoi("8");
	}
	else if (rand() == 200){
		return rand();
	}
	else if (rand() == 700){
		return oneOf3();
	}
	else if (rand() == 9000){
		return 77;
	}
	return x+5;
}


int getNumber2(){
	return getNumber() + atoi("8");
}


int return3(){
	return 3;
}

int getrand(){
	return rand() + rand();
}


int getarg1(int j){
	return j+4;
}

int phidemo(){
	int x = 0;
	if (rand() > 100){
		x = 100;
	}
	else if (rand() > 200){
		x = 700;
	}
	return x;
}

int analyzefun(char * string, int z){
	int x = 9;
	int y = 10;


	malloc(5);
	malloc(x);
	malloc(x + y); //ghidra's analysis figures out that this is 19

	malloc(return3());

	malloc(getNumber()+65);

	malloc(getNumber2());

	malloc(y + return3());

	malloc(strlen(string));

	malloc(z);

	malloc(getarg1(888888));
	
	malloc(phidemo());

	int a = 0x4444;
	if (rand() > 2){
		a = z;
	}
	malloc(a);
}


int analyzefun2(){
	malloc(5);
}

int analyzefun3(){
	malloc(rand());
}


int intermediatefunc2(char * string, int y){
	analyzefun(string, y);
}

int main(int argv, char ** argc) {
	
	analyzefun("foo", 77);

	int zz = recv(0, NULL, 0, 0); 
	analyzefun("bar", zz);
	
	int yy = getrand();
	int jj = getarg1(5);
	intermediatefunc2("bar", yy + jj);

	intermediatefunc2("bar", 100);

	intermediatefunc2("baz", 100 + getNum());
	intermediatefunc2("baz", 99 + getNum());
	
	analyzefun2();
	analyzefun3();
	

}