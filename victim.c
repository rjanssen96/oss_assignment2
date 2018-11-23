#include <stdio.h>
int main(void)
{
  char name[256];
  printf("%p\n",name);
  puts("What’s your name?");
  gets(name);
  printf("Hello, %s!\n", name);
return 0; }
