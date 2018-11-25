#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //Original
  // printf ("system call!\n");
  // thread_exit ();

  //Added
  switch(*(int*)f->esp)
  {
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    case SYS_WRITE:
    {
      //fd = 1, writes to console.
      int fd = *((int*)f->esp + 1);
      // printf("fd = %d\n",fd);
      char* buffer = (char*)(*((int*)f->esp + 2));
      size_t size = *((size_t*)f->esp + 3);
      putbuf(buffer,size);
      break;
    }
    case SYS_EXIT:
    {
      printf("%s: exit(%d)\n", thread_current()->name, 0);
      sema_up(&thread_current()->parent->parent_sema);
      thread_exit();
      break;
    }
    default:
      printf("error %d", (*(int*)f->esp)); 
  }
}


