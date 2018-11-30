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
/* For input */
#include "devices/input.h"

/* Structure to map descriptor to function*/
typedef struct desc_file_mapper
{
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
// static void exit(int status) NO_RETURN;
static pid_t exec(const char *file);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned length);
static int write(int fd, const void *buffer, unsigned length);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
/* For lock */
struct lock file_lock;
/* For Retieving file desciptors or file*/
void *get_file(int fd, bool file);

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
    f->eax = exec((const char *)*(esp + 1));
    break;
  case SYS_WAIT:
    f->eax = wait(*(esp + 1));
    break;
  case SYS_CREATE:
    f->eax = create((char *)*(esp + 1), *(esp + 2));
    break;
  case SYS_REMOVE:
    f->eax = remove((char *)*(esp + 1));
    break;
  case SYS_OPEN:
    f->eax = open((char *)*(esp + 1));
    break;
  case SYS_FILESIZE:
    f->eax = filesize(*(esp + 1));
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
    exit(-1);
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

void exit(int status)
{
  struct thread *t = thread_current();
  struct child_exit_status *ces;
  printf("%s: exit(%d)\n", t->name, status);
  // printf("###%s: exit(%d) tid =%d\n", t->name, status, t->tid);
  //If parent is alive, then add it to child exit list
  if (t->parent != NULL)
  {
    ces =  malloc(sizeof(struct child_exit_status));
    ces->exit_status = status;
    ces->tid = t->tid;
    t = t->parent;
    list_push_back(&t->child_status_list, &ces->elem);
    if(!t->exec_called)
      sema_up(&t->parent_sema);
  }

  // //Close the exe_file if exists
  // if(t->exe_file){
  //   // printf("Closing exe file");
  //   file_allow_write(t->exe_file);
  //   file_close(t->exe_file);
  // }

  //Close all the file descriptors
  // df_map *dfm;
  // struct list_elem *l;
  // for(l = list_begin(&t->desc_file_list); l!=list_end(&t->desc_file_list);l=list_next(l)){
  //   printf("Freeing dfm\n");
  //   l=list_pop_front(&t->desc_file_list);
  //   dfm=list_entry(l, df_map, elem);
  //   file_close(dfm->f);
  //   free(dfm);
  // }

  // //Free all the child statuses
  // while(!list_empty(&t->child_status_list)){
  //   printf("Freeing ces\n");
  //   l=list_pop_front(t->child_status_list);
  //   ces = list_entry(l, struct child_exit_status, elem);
  //   free(ces);
  // }
  thread_exit();
}

static pid_t exec(const char *file)
{
  pid_t pid=-1;
  //Bad pointer
  if (!validate_address((void *)file))
    exit(-1);
  lock_acquire(&file_lock);
  struct thread *t = thread_current();
  t->exec_called = true;
  // printf("EXECing %s\n",file);
  pid = process_execute(file);
  // printf("Exec Returned pid=%d\n",pid);
  sema_down(&t->parent_sema);
  t->exec_called = false;
  lock_release(&file_lock);
  return (t->exec_success) ? pid : -1;
}

static int wait(pid_t pid)
{
  return process_wait(pid);
}

static bool create(const char *file, unsigned initial_size)
{
  //If no file name OR bad pointer
  if (file == NULL || !validate_address((void *)file))
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
  bool result;
  //If no file name
  if (file == NULL)
    exit(-1);
  else
  {
    lock_acquire(&file_lock);
    result = filesys_remove(file);
    lock_release(&file_lock);
  }
  return result;
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

static int filesize(int fd)
{
  int code = -1;
  //Find the file
  df_map *df = get_file(fd, false);
  if (df != NULL){
    lock_acquire(&file_lock);
    code = file_length(df->f);
    lock_release(&file_lock);
  }
  return code;
}

static int read(int fd, void *buffer, unsigned length)
{
  off_t code = -1;
  if (buffer == NULL || !validate_address(buffer))
    exit(-1);
  else if (fd == 0)
    code = input_getc();
  else
  {
    //Find the file
    df_map *df = get_file(fd, false);
    if (df != NULL){
      lock_acquire(&file_lock);
      code = file_read(df->f, buffer, length);
      lock_release(&file_lock);
    }
  }
  return code;
}

static int write(int fd, const void *buffer, unsigned length)
{
  int code = -1;
  if (buffer == NULL || !validate_address((void *)buffer))
    exit(-1);
  //Write to console
  else if (fd == 1)
  {
    putbuf(buffer, length);
    code = 1;
  }
  //Unknown case
  else
  {
    //Find the file
    df_map *df = get_file(fd, false);
    if (df != NULL){
      lock_acquire(&file_lock);
      code = file_write(df->f, buffer, length);
      lock_release(&file_lock);
    }
  }
  //Success
  return code;
}

static void seek(int fd, unsigned position)
{
  df_map *df = get_file(fd, false);
  if (df != NULL){
    lock_acquire(&file_lock);
    file_seek(df->f, (off_t)position);
    lock_release(&file_lock);
  }
  return;
}

static unsigned tell(int fd)
{
  off_t count = -1;
  df_map *df = get_file(fd, false);
  if (df != NULL){
    lock_acquire(&file_lock);
    count = file_tell(df->f);
    lock_release(&file_lock);
  }
  return count;
}

static void close(int fd)
{
  struct thread *t = thread_current();
  df_map *dfm;
  struct list_elem *l;
  for (l = list_begin(&t->desc_file_list); l != list_end(&t->desc_file_list); l = list_next(l))
  {
    dfm = list_entry(l, df_map, elem);
    if (fd == dfm->fd)
    {
      //Close the file
      lock_acquire(&file_lock);
      file_close(dfm->f);
      //Remove from descriptor list
      list_remove(l);
      //Free memory
      free(dfm);
      lock_release(&file_lock);
      break;
    }
  }
}

/* Returns NULL if no file or illegal file desriptor */
void *get_file(int fd, bool return_file)
{
  struct thread *t = thread_current();
  df_map *dfm = NULL;

  //If file descriptor is missing
  if (list_empty(&t->desc_file_list))
    return NULL;
  //Search for given fd in the list
  for (struct list_elem *l = list_begin(&t->desc_file_list); l != list_end(&t->desc_file_list); l = list_next(l))
  {
    dfm = list_entry(l, df_map, elem);
    if (fd == dfm->fd)
      break;
  }

  if (dfm->fd == fd)
    return (return_file) ? (void *)dfm->f : (void *)dfm;
  return NULL;
}