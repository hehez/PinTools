#include <stdio.h>


int fnc_a()
{
		printf("fnc_a called\n");
}

int fnc_b()
{
		printf("fnc_b called\n");
}

int fnc_c()
{
		printf("fnc_c called\n");
}

int fnc_d()
{
		printf("fnc_d called\n");
}

int main(int argc, char **argv)
{
		int num;

		if(argc < 2) {
				printf("./branch integer_argument\n");
				return 0;
		}

		num = atoi(argv[1]);
		if(num%2) fnc_a();
		else fnc_b();

		if(num > 10) fnc_c();
		else fnc_d();

		return 1;
}

