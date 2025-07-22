/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - Main Module
 * 
 * This is the main entry point for the kernel driver remote debugging
 * and tracing system. It initializes all subsystems and provides the
 * core module functionality.
 */

#include "kernel_debug_tracer.h"

/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Debug Tracer Team");
MODULE_DESCRIPTION("Remote debugging and tracing system for kernel drivers");
MODULE_VERSION("1.0.0");

/* Module parameters */
static char *target_module = "";
module_param(target_module, charp, 0644);
MODULE_PARM_DESC(target_module, "Target kernel module to debug");

static bool enable_on_load = false;
module_param(enable_on_load, bool, 0644);
MODULE_PARM_DESC(enable_on_load, "Enable tracing immediately on module load");

static int max_events = MAX_EVENTS;
module_param(max_events, int, 0644);
MODULE_PARM_DESC(max_events, "Maximum number of events to store");

/* Global tracer state */
struct debug_tracer_state tracer_state = {
    .config = {
        .enabled = false,
        .max_events = MAX_EVENTS,
        .stack_depth_limit = MAX_STACK_DEPTH,
        .trace_function_calls = true,
        .trace_variable_changes = true,
        .target_module = "",
        .filter_mask = 0
    },
    .breakpoints = LIST_HEAD_INIT(tracer_state.breakpoints),
    .events = LIST_HEAD_INIT(tracer_state.events),
    .breakpoints_lock = __SPIN_LOCK_UNLOCKED(tracer_state.breakpoints_lock),
    .events_lock = __SPIN_LOCK_UNLOCKED(tracer_state.events_lock),
    .event_count = 0,
    .debugfs_root = NULL,
    .initialized = false
};

/**
 * update_module_params - Update configuration from module parameters
 */
static void update_module_params(void)
{
    if (target_module && strlen(target_module) > 0) {
        strncpy(tracer_state.config.target_module, target_module, 
                MODULE_NAME_MAX - 1);
        tracer_state.config.target_module[MODULE_NAME_MAX - 1] = '\0';
    }
    
    tracer_state.config.enabled = enable_on_load;
    
    if (max_events > 0 && max_events <= MAX_EVENTS * 10) {
        tracer_state.config.max_events = max_events;
    }
}

/**
 * debug_tracer_init - Initialize the debug tracer system
 */
int debug_tracer_init(void)
{
    int ret = 0;
    
    pr_info("Kernel Debug Tracer: Initializing...\n");
    
    /* Initialize breakpoint manager */
    ret = bp_manager_init();
    if (ret) {
        pr_err("Failed to initialize breakpoint manager: %d\n", ret);
        goto err_bp_manager;
    }
    
    /* Initialize symbol resolver */
    ret = symbol_resolver_init(tracer_state.config.target_module);
    if (ret) {
        pr_err("Failed to initialize symbol resolver: %d\n", ret);
        goto err_symbol_resolver;
    }
    
    /* Initialize kprobe handler */
    ret = kprobe_handler_init();
    if (ret) {
        pr_err("Failed to initialize kprobe handler: %d\n", ret);
        goto err_kprobe_handler;
    }
    
    /* Initialize call stack tracer */
    ret = call_stack_tracer_init();
    if (ret) {
        pr_err("Failed to initialize call stack tracer: %d\n", ret);
        goto err_call_stack_tracer;
    }
    
    /* Initialize variable extractor */
    ret = variable_extractor_init();
    if (ret) {
        pr_err("Failed to initialize variable extractor: %d\n", ret);
        goto err_variable_extractor;
    }
    
    /* Initialize data collector */
    ret = data_collector_init();
    if (ret) {
        pr_err("Failed to initialize data collector: %d\n", ret);
        goto err_data_collector;
    }
    
    /* Initialize debugfs interface */
    ret = debugfs_interface_init();
    if (ret) {
        pr_err("Failed to initialize debugfs interface: %d\n", ret);
        goto err_debugfs_interface;
    }
    
    tracer_state.initialized = true;
    pr_info("Kernel Debug Tracer: Initialization complete\n");
    
    return 0;

err_debugfs_interface:
    data_collector_exit();
err_data_collector:
    variable_extractor_exit();
err_variable_extractor:
    call_stack_tracer_exit();
err_call_stack_tracer:
    kprobe_handler_exit();
err_kprobe_handler:
    symbol_resolver_exit();
err_symbol_resolver:
    bp_manager_exit();
err_bp_manager:
    return ret;
}

/**
 * debug_tracer_exit - Cleanup the debug tracer system
 */
void debug_tracer_exit(void)
{
    pr_info("Kernel Debug Tracer: Shutting down...\n");
    
    if (!tracer_state.initialized)
        return;
    
    /* Disable tracing first */
    tracer_state.config.enabled = false;
    
    /* Cleanup subsystems in reverse order */
    debugfs_interface_exit();
    data_collector_exit();
    variable_extractor_exit();
    call_stack_tracer_exit();
    kprobe_handler_exit();
    symbol_resolver_exit();
    bp_manager_exit();
    
    tracer_state.initialized = false;
    pr_info("Kernel Debug Tracer: Shutdown complete\n");
}

/**
 * kernel_debug_tracer_init - Module initialization function
 */
static int __init kernel_debug_tracer_init(void)
{
    int ret;
    
    pr_info("Loading Kernel Debug Tracer module\n");
    
    /* Apply module parameters first */
    update_module_params();
    
    ret = debug_tracer_init();
    if (ret) {
        pr_err("Failed to initialize debug tracer: %d\n", ret);
        return ret;
    }
    
    pr_info("Kernel Debug Tracer module loaded successfully\n");
    return 0;
}

/**
 * kernel_debug_tracer_exit - Module cleanup function
 */
static void __exit kernel_debug_tracer_exit(void)
{
    pr_info("Unloading Kernel Debug Tracer module\n");
    
    debug_tracer_exit();
    
    pr_info("Kernel Debug Tracer module unloaded\n");
}

/* Register module init and exit functions */
module_init(kernel_debug_tracer_init);
module_exit(kernel_debug_tracer_exit);