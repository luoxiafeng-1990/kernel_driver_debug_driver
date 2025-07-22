/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - Data Collector
 * 
 * This module collects and manages debug events and trace data.
 * It provides storage, retrieval, and filtering capabilities.
 */

#include "kernel_debug_tracer.h"

/* Static function declarations */
static void cleanup_old_events(void);
static bool event_matches_filter(struct debug_event *event, const char *filter);
static struct debug_event *alloc_debug_event(void);
static void free_debug_event(struct debug_event *event);

/**
 * data_collector_init - Initialize the data collector
 * 
 * Return: 0 on success, negative error code on failure
 */
int data_collector_init(void)
{
    pr_debug("Data Collector: Initializing\n");
    
    /* Initialize event list if not already done */
    if (list_empty(&tracer_state.events)) {
        INIT_LIST_HEAD(&tracer_state.events);
    }
    
    tracer_state.event_count = 0;
    
    pr_debug("Data Collector: Initialization complete\n");
    return 0;
}

/**
 * data_collector_exit - Cleanup the data collector
 */
void data_collector_exit(void)
{
    pr_debug("Data Collector: Shutting down\n");
    
    /* Clear all events */
    data_collector_clear();
    
    pr_debug("Data Collector: Shutdown complete\n");
}

/**
 * data_collector_add_event - Add a debug event to the collection
 * @event: Debug event to add
 * 
 * Return: 0 on success, negative error code on failure
 */
int data_collector_add_event(struct debug_event *event)
{
    unsigned long flags;
    
    if (!event) {
        return -EINVAL;
    }
    
    pr_debug("Adding debug event: type=%s, addr=0x%lx\n", 
             event->event_type, event->trigger_addr);
    
    spin_lock_irqsave(&tracer_state.events_lock, flags);
    
    /* Check if we need to make room for new event */
    if (tracer_state.event_count >= tracer_state.config.max_events) {
        cleanup_old_events();
    }
    
    /* Add event to list */
    list_add_tail(&event->list, &tracer_state.events);
    tracer_state.event_count++;
    
    spin_unlock_irqrestore(&tracer_state.events_lock, flags);
    
    pr_debug("Event added successfully (total: %d)\n", tracer_state.event_count);
    return 0;
}

/**
 * data_collector_get_events - Retrieve debug events with optional filtering
 * @events: Pointer to store array of events (allocated by this function)
 * @count: Pointer to store number of events returned
 * @filter: Filter string (can be NULL for no filtering)
 * 
 * Return: 0 on success, negative error code on failure
 */
int data_collector_get_events(struct debug_event **events, int *count, 
                             const char *filter)
{
    struct debug_event *event, *event_copy;
    struct debug_event **event_array;
    unsigned long flags;
    int matched_count = 0;
    int i = 0;
    
    if (!events || !count) {
        return -EINVAL;
    }
    
    pr_debug("Getting events with filter: '%s'\n", filter ? filter : "none");
    
    /* First pass: count matching events */
    spin_lock_irqsave(&tracer_state.events_lock, flags);
    list_for_each_entry(event, &tracer_state.events, list) {
        if (!filter || event_matches_filter(event, filter)) {
            matched_count++;
        }
    }
    spin_unlock_irqrestore(&tracer_state.events_lock, flags);
    
    if (matched_count == 0) {
        *events = NULL;
        *count = 0;
        return 0;
    }
    
    /* Allocate array for event pointers */
    event_array = kzalloc(sizeof(*event_array) * matched_count, GFP_KERNEL);
    if (!event_array) {
        return -ENOMEM;
    }
    
    /* Second pass: copy matching events */
    spin_lock_irqsave(&tracer_state.events_lock, flags);
    list_for_each_entry(event, &tracer_state.events, list) {
        if (i >= matched_count) {
            break;
        }
        
        if (!filter || event_matches_filter(event, filter)) {
            /* Allocate and copy event */
            event_copy = alloc_debug_event();
            if (event_copy) {
                memcpy(event_copy, event, sizeof(*event_copy));
                INIT_LIST_HEAD(&event_copy->list);  /* Clear list linkage */
                event_array[i++] = event_copy;
            }
        }
    }
    spin_unlock_irqrestore(&tracer_state.events_lock, flags);
    
    *events = (struct debug_event *)event_array;
    *count = i;
    
    pr_debug("Retrieved %d events (matched %d)\n", i, matched_count);
    return 0;
}

/**
 * data_collector_clear - Clear all collected events
 */
void data_collector_clear(void)
{
    struct debug_event *event, *tmp;
    unsigned long flags;
    
    pr_debug("Clearing all collected events\n");
    
    spin_lock_irqsave(&tracer_state.events_lock, flags);
    list_for_each_entry_safe(event, tmp, &tracer_state.events, list) {
        list_del(&event->list);
        free_debug_event(event);
    }
    tracer_state.event_count = 0;
    spin_unlock_irqrestore(&tracer_state.events_lock, flags);
    
    pr_debug("All events cleared\n");
}

/**
 * cleanup_old_events - Remove old events to make room for new ones
 * 
 * Note: Caller must hold events_lock
 */
static void cleanup_old_events(void)
{
    struct debug_event *event, *tmp;
    int events_to_remove = tracer_state.config.max_events / 4;  /* Remove 25% */
    int removed = 0;
    
    pr_debug("Cleaning up old events (removing %d)\n", events_to_remove);
    
    /* Remove oldest events (from head of list) */
    list_for_each_entry_safe(event, tmp, &tracer_state.events, list) {
        if (removed >= events_to_remove) {
            break;
        }
        
        list_del(&event->list);
        free_debug_event(event);
        tracer_state.event_count--;
        removed++;
    }
    
    pr_debug("Removed %d old events\n", removed);
}

/**
 * event_matches_filter - Check if event matches filter criteria
 * @event: Event to check
 * @filter: Filter string
 * 
 * Return: true if event matches, false otherwise
 */
static bool event_matches_filter(struct debug_event *event, const char *filter)
{
    if (!event || !filter) {
        return true;  /* No filter means match all */
    }
    
    /* Simple string matching for now */
    /* TODO: Implement more sophisticated filtering */
    
    /* Check event type */
    if (strstr(event->event_type, filter)) {
        return true;
    }
    
    /* Check if filter is a hex address */
    if (strncmp(filter, "0x", 2) == 0) {
        unsigned long addr;
        if (kstrtoul(filter, 16, &addr) == 0) {
            if (event->trigger_addr == addr) {
                return true;
            }
        }
    }
    
    /* Check function names in call stack */
    for (int i = 0; i < event->call_stack.depth; i++) {
        if (strstr(event->call_stack.frames[i].func_name, filter)) {
            return true;
        }
    }
    
    return false;
}

/**
 * alloc_debug_event - Allocate a new debug event structure
 * 
 * Return: Pointer to allocated event, NULL on failure
 */
static struct debug_event *alloc_debug_event(void)
{
    struct debug_event *event;
    
    event = kzalloc(sizeof(*event), GFP_ATOMIC);
    if (!event) {
        pr_err("Failed to allocate memory for debug event\n");
        return NULL;
    }
    
    INIT_LIST_HEAD(&event->list);
    return event;
}

/**
 * free_debug_event - Free a debug event structure
 * @event: Event to free
 */
static void free_debug_event(struct debug_event *event)
{
    if (event) {
        /* Free any dynamically allocated data within the event */
        /* TODO: Free variable data if dynamically allocated */
        kfree(event);
    }
}