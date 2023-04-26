char *x;

void foo()
{
  char buffer[400];
  x = &buffer[1];
}

int main()
{
  foo();
  *x = 42;

  return 0;
}
