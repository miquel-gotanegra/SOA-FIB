#include <piper.h>
#include <sched.h>

struct opened_file opened_file_table[MAX_PIPES];
struct list_head free_pipe;
extern struct list_head readyqueue;

/*
 *
 */
void init_pipes()
{
	INIT_LIST_HEAD(&free_pipe);
	for (int i = 0; i < MAX_PIPES; ++i){
		list_add_tail(&(opened_file_table[i].list), &free_pipe);
		opened_file_table[i].num_referencias=0;
	}
}

/*
 * 
 */
int sem_init(struct semaphore * p, unsigned int value)
{
	p->count = value;
	INIT_LIST_HEAD(&(p->blocked));
	return 0;
}

/*
 *
 */
int sem_wait(struct semaphore * p)
{
	if (p->count <= 0) {
		update_process_state_rr(current(), &p->blocked);
		sched_next_rr();
	}
	else --(p->count);
	return 0;
}

/*
 *
 */
int sem_signal(struct semaphore * p)
{
	++(p->count);
	if (!list_empty(&p->blocked)) {
		struct list_head * l = list_first(&p->blocked);
		list_del(l);
		struct task_struct * t = list_head_to_task_struct(l);
		update_process_state_rr(t, &readyqueue);
	}
	else return -1;
	return 0;
}

/*
 *
 */
int sem_destroy(struct semaphore * p)
{
	if (!list_empty(&p->blocked)) printk("sem_destroy: La lista de blocked no esta vacía.");
	return 0;
}


