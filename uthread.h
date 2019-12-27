#ifndef CALAB_SELECTION_UTHREAD_H
#define CALAB_SELECTION_UTHREAD_H
#include "list.h"

void sched(struct list *t_list);
void yield();

#endif // CALAB_SELECTION_UTHREAD_H