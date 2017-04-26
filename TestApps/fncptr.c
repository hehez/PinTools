#include <stdio.h>
#include <stdlib.h>

void fnc_a(int i)
{
		printf("fnc_a called: %d\n", i);
}

void fnc_b(int i)
{
		printf("fnc_b called: %d\n", i);
}

void fnc_c(int i)
{
		printf("fnc_c called: %d\n", i);
}

void fnc_d(int i)
{
		printf("fnc_d called: %d\n", i);
}

int main(int argc, char **argv)
{
		int num;
		void (*fun_ptr)(int);

		if(argc < 2) {
				printf("./branch integer_argument\n");
				return 0;
		}

		num = atoi(argv[1]);
	// fun_ptr is a pointer to function fun() 

		/* The above line is equivalent of following two
					void (*fun_ptr)(int);
					fun_ptr = &fun; 
			*/

		// Invoking fun() using fun_ptr
		if(num%2) fun_ptr = &fnc_a;
		else fun_ptr = &fnc_b;
		(*fun_ptr)(num);

		if(num > 10) fun_ptr = &fnc_c;
		else fun_ptr = &fnc_d;

		(*fun_ptr)(num);

		return 0;
}

