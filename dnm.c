
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void func1(int b, int c)
{
	int a = b + c;
	printf("%d\n", a);
}

int func2(void)
{
	func1(1,2);
	return EXIT_SUCCESS;
}

void func3(int b, int c)
{
	func1(b+1,c-1);
}

int main(int argc, char *argv[])
{
	__asm__("movl $0x1234, 0x1000(%rip)");

	int ret = EXIT_FAILURE;
	srand(time(NULL));
	if (rand() % 3)
		ret = func2();
	else
		func3(3,4);
	if (!ret)
		printf("func2 executed and completed successfully\n");

	char **ptr1;
	char *ptr2;
	char str = 'i';
	ptr2 = &str;
	ptr1 = &ptr2;
	printf("%c: %x\n", **ptr1, ptr1);

	return EXIT_SUCCESS;
}
