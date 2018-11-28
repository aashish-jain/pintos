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
/* For file allow write */
#include "filesys/file.h"
/* For malloc */
#include "threads/malloc.h"

/* Structure to map descriptor to function*/
typedef struct desc_file_mapper{
  int fd;
  struct file *f;
  struct list_elem elem;
} df_map;


static void syscall_handler(struct intr_frame *);

//Added
typedef int pid_t;
static bool validate_address(void *address);
static void safe_memory_access(int *addr);
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
/* For lock */
struct lock file_lock;
/* For Retieving file desciptors */
// struct file* get_file(unsigned int fd);

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
  int *esp = f->esp;
  safe_memory_access(esp);
  switch (*esp)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    exit(*(esp + 1));
    break;
  case SYS_EXEC:
    f->eax = exec((char *)*(esp + 1));
    break;
  case SYS_WAIT:
    wait(*(esp + 1));
    break;
  case SYS_CREATE:
    f->eax = create((char *)*(esp + 1), *(esp + 2));
    break;
  case SYS_REMOVE:
    f->eax = filesize(*(esp + 1));
    break;
  case SYS_OPEN:
    f->eax = open((char *)*(esp + 1));
    break;
  case SYS_FILESIZE:
    break;
  case SYS_READ:
    f->eax = read(*(esp + 1), (char *)*(esp + 2), *(esp + 3));
    break;
  case SYS_WRITE:
    f->eax = write(*(esp + 1), (char *)*(esp + 2), *(esp + 3));
    break;
  case SYS_SEEK:
    seek(*(esp + 1), *(esp + 2));
    break;
  case SYS_TELL:
    f->eax = tell(*(esp + 1));
    break;
  case SYS_CLOSE:
    close(*(esp + 1));
    break;
  default:
    printf("error %d", (*(int *)f->esp));
  }
}

static void safe_memory_access(int *addr)
{
  //There are at max 3 arguments that will be in the stack
  int safe_access = validate_address(addr) + validate_address(addr + 1) +
                    validate_address(addr + 2) + validate_address(addr + 3);
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
  // struct child_exit_status *ces = malloc(sizeof(struct child_exit_status));

  printf("%s: exit(%d)\n", thread_current()->name, status);
  if (t->parent != NULL)
  {
    t = t->parent;
    sema_up(&t->parent_sema);
  }
  thread_exit();
}

static pid_t exec(const char *file)
{
  //Bad pointer
  if(!validate_address((void*)file))
    exit(-1);
  struct thread *t = thread_current();
  t->exec_wait_called = true;
  process_execute(file);
  sema_down(&t->parent_sema);
  t->exec_wait_called = false;
  return t->child_exec_status;
}

static int wait(pid_t pid)
{
  struct thread *t = thread_current();
  t->exec_wait_called = true;
  int status = process_wait(pid);
  t->exec_wait_called = false;
  return status;
}

static bool create(const char *file, unsigned initial_size)
{
  //If no file name OR bad pointer
  if (file == NULL || !validate_address((void*)file))
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
  //If no file name given
  if (file == NULL)
    return -1;
  //If bad pointer
  if (!validate_address((void *)file))
    exit(-1);

  struct thread *t = thread_current();
  df_map *dfm = malloc(sizeof(df_map));
  lock_acquire(&file_lock);
  dfm->f = filesys_open(file);
  lock_release(&file_lock);

  //Missing file
  if (dfm->f == NULL)
    return -1;
  //Else set fd=2 if no elements in desc_file_list
  else if (list_empty(&t->desc_file_list))
    dfm->fd = 2;
  //Else fd = last file descriptor + 1
  else
    dfm->fd = (list_entry(list_back(&t->desc_file_list), df_map, elem)->fd) + 1;
  list_push_back(&t->desc_file_list, &(dfm->elem));
  return dfm->fd;
}

static int filesize(int fd UNUSED)
{
  //YET TO IMPLEMENT
  //We need to use file_lenght() here
  return 1;
}

static int read(int fd UNUSED, void *buffer, unsigned length UNUSED)
{
  if (buffer == NULL || !validate_address(buffer))
    exit(-1);
  return 1;
}

static int write(int fd, const void *buffer, unsigned length)
{
  if (buffer == NULL || !validate_address((void*)buffer))
    exit(-1);
  //Write to console
  else if(fd==1)
    putbuf(buffer, length);
  //Unknown case
  else
    exit(-1);
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

static void close(int fd)
{
  struct thread *t = thread_current();
  df_map *fdm;
  struct list_elem *l;
  for (l = list_begin(&t->desc_file_list); l != list_end(&t->desc_file_list); l = list_next(l))
  {
    fdm = list_entry(l, df_map, elem);
    if(fd == fdm->fd){
      file_close(fdm->f);
      list_remove(l);
    }
  }
}

// /* Returns NULL if no file or illegal file desriptor */
// struct file* get_file(unsigned int fd){
//   struct thread *t=thread_current();
//   if(list_empty(t))
//     return NULL;
  
// }