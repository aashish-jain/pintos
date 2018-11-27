#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
//Added
/* For shutdown poweroff */
#include "devices/shutdown.h"
/* For process_execute*/
#include "userprog/process.h"
/* For file operations */
#include "filesys/filesys.h"

//Added
typedef int pid_t;
static bool validate_address(void *address);
static void safe_memory_access(void *addr);
static void syscall_handler(struct intr_frame *);
//Added
/* For lock */
struct lock file_lock;

//Added
/* Function prototypes from /usr/sycall.h */
static void halt(void) NO_RETURN;
static void exit(int status) NO_RETURN;
static pid_t exec(const char *file);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file) UNUSED;
static int open(const char *file);
static int filesize(int fd) UNUSED;
static int read(int fd, void *buffer, unsigned length);
static int write(int fd, const void *buffer, unsigned length);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  //Added
  lock_init(&file_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  //Original
  // printf ("system call!\n");
  // thread_exit ();

  //Added
  safe_memory_access(f->esp);
  switch (*(int *)f->esp)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    exit(*((int *)f->esp + 1));
    break;
  case SYS_EXEC:
    exec((char *)(*((int *)f->esp + 1)));
    break;
  case SYS_WAIT:
    wait((*((pid_t *)f->esp + 1)));
    break;
  case SYS_CREATE:
    f->eax = create((char *)(*((int *)f->esp + 1)), *((int *)f->esp + 2));
    break;
  case SYS_REMOVE:
    f->eax = filesize((*((int *)f->esp + 1)));
    break;
  case SYS_OPEN:
    open((char *)(*((int *)f->esp + 2)));
    break;
  case SYS_FILESIZE:
    break;
  case SYS_READ:
    read(*((int *)f->esp + 1), (char *)(*((int *)f->esp + 2)), *((size_t *)f->esp + 3));
    break;
  case SYS_WRITE:
    write(*((int *)f->esp + 1), (char *)(*((int *)f->esp + 2)), *((size_t *)f->esp + 3));
    break;
  case SYS_SEEK:
    seek((*((int *)f->esp + 1)), (size_t)(*((int *)f->esp + 2)));
    break;
  case SYS_TELL:
    f->eax = tell((*((int *)f->esp + 1)));
    break;
  case SYS_CLOSE:
    close(*((int *)f->esp + 1));
    break;
  default:
    printf("error %d", (*(int *)f->esp));
  }
}

static void safe_memory_access(void *addr)
{
  //There are at max 3 arguments that will be in the stack
  int safe_access = validate_address((int *)addr) + validate_address((int *)addr + 1) +
                    validate_address((int *)addr + 2) + validate_address((int *)addr + 3);
  if (safe_access != 4)
    exit(-1);
}

static bool validate_address(void *address)
{
  // check if the pointer is within PHYS_BASE or in the thread's page
  return is_user_vaddr(address) && pagedir_get_page(thread_current()->pagedir, address) != NULL;
}

static void halt()
{
  shutdown_power_off();
}

static void exit(int status)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if (t->parent != NULL)
  {
    t = t->parent;
    //Place holder. Need to fix it.
    sema_up(&thread_current()->parent->parent_sema);
  }
  thread_exit();
}

static pid_t exec(const char *file)
{
  struct thread *t = thread_current();
  t->exec_wait_called = true;
  // printf("tid=%d is calling exec\n",t->tid);
  process_execute(file);
  sema_down(&t->parent_sema);
  t->exec_wait_called = false;
  return t->child_exec_status;
}

static int wait(pid_t pid)
{
  return  process_wait(pid);
}

static bool create(const char *file, unsigned initial_size UNUSED)
{
  //If no file name
  if (file == NULL)
    exit(-1);
  else
  {
    lock_acquire(&file_lock);
    bool result = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return result;
  }
}

static bool remove(const char *file) 
{
  //If no file name
  if (file == NULL)
    exit(-1);
  else
  {
    lock_acquire(&file_lock);
    bool result = filesys_remove(file);
    lock_release(&file_lock);
    return result;
  }
}

static int open(const char *file)
{
  if (file == NULL)
    exit(-1);
  return 1;
}

static int filesize(int fd UNUSED)
{
  //YET TO IMPLEMENT
  //We need to use file_lenght() here
  return 1;
}

static int read(int fd, void *buffer UNUSED, unsigned length UNUSED)
{
  if (buffer == NULL)
    exit(-1);

  //TODO: check if the reading is within limits(use file_size)
  switch (fd)
  {
  //Uknown descriptor then return error
  default:
    exit(-1);
  }
  //Success
  return 1;
}

static int write(int fd, const void *buffer, unsigned length)
{
  if (buffer == NULL)
    exit(-1);
  switch (fd)
  {
  //Console
  case 1:
    putbuf(buffer, length);
    break;
  //Uknown descriptor then return error
  default:
    exit(-1);
  }
  //Success
  return 1;
}

static void seek(int fd UNUSED, unsigned position UNUSED)
{
  //YET TO IMPLEMENT
  //We need to use file_seek() here
}

static unsigned tell(int fd UNUSED)
{
  //YET TO IMPLEMENT
  //We need to use file_tell() here
  return 1;
}

static void close(int fd UNUSED)
{
  return;
}