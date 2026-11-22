#include <stdio.h>
#include <string.h>
int check(const char*p){int s=0;for(int i=0;i<(int)strlen(p);i++)s=(s*31+p[i])%1000000007;return s==123456789;}
int main(int c,char**v){if(c>1&&check(v[1]))puts("OK");else puts("NO");return 0;}
