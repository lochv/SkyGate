#pragma once

#include <windows.h>

typedef struct node {
	DWORD pid;

	DWORD create_time_dwLowDateTime;
	DWORD create_time_dwHighDateTime;

	struct node* next;
} PROCESS_INJECTION_MUTEX;


bool init_process_injection_mutex(DWORD pid, PROCESS_INJECTION_MUTEX* process_injection_mutex);


bool operator==(const PROCESS_INJECTION_MUTEX&, const PROCESS_INJECTION_MUTEX&);

//void push_node_to_list(struct node** head_ref, DWORD pid, DWORD create_time_dwLowDateTime, DWORD create_time_dwHighDateTime);
void push_node_to_list(struct node** head_ref, struct node* new_node);
struct node* find_node_in_list(struct node* head, struct node n);
void delete_node_in_list(struct node **head_ref, struct node* n);
void copy_list(struct node** dest_head_ref, struct node* source_head);
void delete_list(struct node** head_ref);
void remove_dead_processes_from_list(struct node** head);
void print_list(struct node* head);


//
char* get_process_name(DWORD pid);

char* get_process_command_line(DWORD pid);

DWORD get_process_id_by_name(char* process_name);

