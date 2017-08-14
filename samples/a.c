#include <stdio.h>

void
call(int i) {
  printf("test %d\n", i);
}

int
main() {
  for (int i = 0; i < 10; ++i) {
    call(i);
  }
}
