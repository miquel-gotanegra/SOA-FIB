#include <libc.h>

char buff[24];

int pid;

int __attribute__ ((__section__(".text.main")))
  main(void)
{
    /* Next line, tries to move value 0 to CR3 register. This register is a privileged one, and so it will raise an exception */
     /* __asm__ __volatile__ ("mov %0, %%cr3"::"r" (0) ); */

  int pd[2];
  pipe(&pd);
  char * buffer = "Pipe";
  int pid = fork();
  if (pid == 0){
    read(pd[0], buff, 4);
    write(1, buff, 4);
  }
  else write(pd[1], buffer, 4);

  
  while(1) { }
}
