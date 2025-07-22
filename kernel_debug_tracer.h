/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - Core Header File
 * 
 * This file defines the core data structures and interfaces for the
 * kernel driver remote debugging and tracing system.
 */

#ifndef _KERNEL_DEBUG_TRACER_H
#define _KERNEL_DEBUG_TRACER_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/ptrace.h>

/* Constants */
#define FUNC_NAME_MAX       128
#define VAR_NAME_MAX        64
#define TYPE_NAME_MAX       64
#define VALUE_STR_MAX       256
#define MODULE_NAME_MAX     64
#define MAX_STACK_DEPTH     32
#define MAX_VARS_PER_EVENT  16
#define MAX_VAR_SIZE        1024
#define MAX_EVENTS          10000

/* Error codes */
enum debug_error {
    DEBUG_SUCCESS = 0,
    DEBUG_ERROR_INVALID_ADDR = -1,
    DEBUG_ERROR_SYMBOL_NOT_FOUND = -2,
    DEBUG_ERROR_KPROBE_FAILED = -3,
    DEBUG_ERROR_MEMORY_ACCESS = -4,
    DEBUG_ERROR_BUFFER_FULL = -5,
    DEBUG_ERROR_MODULE_NOT_LOADED = -6,
    DEBUG_ERROR_PERMISSION_DENIED = -7
};

/* Forward declarations */
struct breakpoint_info;
struct symbol_info;
struct variable_info;
struct debug_event;
struct debug_config;

/* Breakpoint information structure */
struct breakpoint_info {
    struct list_head list;
    unsigned long addr;          /* Kernel address */
    char source_file[PATH_MAX];  /* Source file path */
    int line_number;             /* Line number */
    char function_name[FUNC_NAME_MAX]; /* Function name */
    bool enabled;                /* Is breakpoint enabled */
    int hit_count;               /* Number of times hit */
    struct kprobe kp;            /* Associated kprobe */
    unsigned long last_hit_time; /* Last hit timestamp */
};

/* Symbol information structure */
struct symbol_info {
    unsigned long addr;
    char name[FUNC_NAME_MAX];
    char file[PATH_MAX];
    int line;
    int size;
};

/* Variable information structure */
struct variable_info {
    char name[VAR_NAME_MAX];
    char type[TYPE_NAME_MAX];
    unsigned long addr;
    int size;
    int offset;  /* Offset relative to stack frame */
};

/* Variable value structure */
struct variable_value {
    char name[VAR_NAME_MAX];
    char type[TYPE_NAME_MAX];
    void *data;
    int size;
    char string_repr[VALUE_STR_MAX];  /* String representation */
};

/* Call frame structure */
struct call_frame {
    unsigned long addr;
    char function_name[FUNC_NAME_MAX];
    char file_name[PATH_MAX];
    int line_number;
};

/* Call stack structure */
struct call_stack {
    int depth;
    struct call_frame frames[MAX_STACK_DEPTH];
};

/* Kprobe context structure */
struct kprobe_context {
    struct pt_regs *regs;       /* Register state */
    unsigned long addr;         /* Trigger address */
    char function_name[FUNC_NAME_MAX]; /* Function name */
    struct task_struct *task;   /* Current task */
    unsigned long timestamp;    /* Timestamp */
};

/* Debug event structure */
struct debug_event {
    struct list_head list;
    unsigned long timestamp;
    pid_t pid;
    pid_t tid;
    unsigned long trigger_addr;
    char event_type[32];
    
    /* Call stack information */
    struct {
        int depth;
        struct {
            unsigned long addr;
            char func_name[FUNC_NAME_MAX];
            char file_name[PATH_MAX];
            int line_no;
        } frames[MAX_STACK_DEPTH];
    } call_stack;
    
    /* Variable information */
    struct {
        int count;
        struct {
            char name[VAR_NAME_MAX];
            char type[TYPE_NAME_MAX];
            unsigned long addr;
            int size;
            char value_str[VALUE_STR_MAX];
            unsigned char raw_data[MAX_VAR_SIZE];
        } vars[MAX_VARS_PER_EVENT];
    } variables;
};

/* Configuration structure */
struct debug_config {
    bool enabled;
    int max_events;
    int stack_depth_limit;
    bool trace_function_calls;
    bool trace_variable_changes;
    char target_module[MODULE_NAME_MAX];
    unsigned long filter_mask;
};

/* Global state structure */
struct debug_tracer_state {
    struct debug_config config;
    struct list_head breakpoints;
    struct list_head events;
    spinlock_t breakpoints_lock;
    spinlock_t events_lock;
    int event_count;
    struct dentry *debugfs_root;
    bool initialized;
};

/* External global state */
extern struct debug_tracer_state tracer_state;

/* Core module functions */
int debug_tracer_init(void);
void debug_tracer_exit(void);

/* Breakpoint manager functions */
int bp_manager_init(void);
void bp_manager_exit(void);
int bp_manager_add_breakpoint(const char *file, int line);
int bp_manager_remove_breakpoint(unsigned long addr);
int bp_manager_enable_breakpoint(unsigned long addr);
int bp_manager_disable_breakpoint(unsigned long addr);
struct breakpoint_info *bp_manager_find_breakpoint(unsigned long addr);

/* Symbol resolver functions */
int symbol_resolver_init(const char *module_name);
void symbol_resolver_exit(void);
struct symbol_info *symbol_resolver_addr_to_symbol(unsigned long addr);
struct variable_info *symbol_resolver_get_function_vars(const char *func_name);
unsigned long symbol_resolver_name_to_addr(const char *symbol_name);

/* Kprobe handler functions */
int kprobe_handler_init(void);
void kprobe_handler_exit(void);
int kprobe_handler_register(unsigned long addr, 
                           int (*pre_handler)(struct kprobe *, struct pt_regs *),
                           void (*post_handler)(struct kprobe *, struct pt_regs *, unsigned long));
int kprobe_handler_unregister(unsigned long addr);

/* Call stack tracer functions */
int call_stack_tracer_init(void);
void call_stack_tracer_exit(void);
int call_stack_tracer_capture(struct call_stack *stack, struct pt_regs *regs);
void call_stack_tracer_print(struct call_stack *stack, char *buffer, int size);

/* Variable extractor functions */
int variable_extractor_init(void);
void variable_extractor_exit(void);
int variable_extractor_get_local_vars(struct pt_regs *regs, 
                                     const char *function_name,
                                     struct variable_value **vars,
                                     int *count);
int variable_extractor_get_global_var(const char *var_name,
                                     struct variable_value *var);

/* Data collector functions */
int data_collector_init(void);
void data_collector_exit(void);
int data_collector_add_event(struct debug_event *event);
int data_collector_get_events(struct debug_event **events, int *count, 
                             const char *filter);
void data_collector_clear(void);

/* Debugfs interface functions */
int debugfs_interface_init(void);
void debugfs_interface_exit(void);

/* Utility functions */
static inline unsigned long get_timestamp(void)
{
    return ktime_get_ns();
}

static inline void debug_print(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (tracer_state.config.enabled)
        vprintk(fmt, args);
    va_end(args);
}

#endif /* _KERNEL_DEBUG_TRACER_H */