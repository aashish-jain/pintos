#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
void validate_address(void *address);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();
  // printf("value : %d\n", *(int*)f->esp);
  validate_address(f->esp);
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
      validate_address((int *)f->esp+1);
      int fd = *((int*)f->esp + 1);
      if(fd == 1)
      {
        validate_address((char *)f->esp+2);
        validate_address((size_t *)f->esp+3);
        // printf("fd = %d\n",fd);
        char* buffer = (char*)(*((int*)f->esp + 2));
        validate_address(buffer);
        size_t size = *((size_t*)f->esp + 3);
        putbuf(buffer,size);
      }
      break;
    }
    case SYS_EXIT:
    {
      // printf("%s: exit(%d)\n", thread_current()->name, 0);
      // sema_up(&thread_current()->parent->parent_sema);
      // thread_exit();
      // printf("f->esp+1 : %p\n",(void *)f->esp+1);
      // printf("f->esp+1 : %p\n",(int *)f->esp+1);
      validate_address((int *)f->esp+1);
      int status = *((int*)f->esp + 1);
      exit(status);
      break;
    }
    default:
      printf("error %d", (*(int*)f->esp)); 
  }
}

void exit(int status){
  thread_current()->error_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  sema_up(&thread_current()->parent->parent_sema);
  thread_exit();  
}

void validate_address(void *address)
{
  // check if the pointer is within PHYS_BASE
  if(is_user_vaddr(address) == NULL)
  {
    exit(-1);
  }
  // the pointer belongs to a page in the virtual memory .
  if(pagedir_get_page(thread_current()->pagedir,address) == NULL)
  {
    exit(-1);
  }
}

