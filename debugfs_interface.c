/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - DebugFS Interface
 * 
 * This module provides the debugfs interface for user-space communication.
 * It creates control files for configuration and data access.
 */

#include "kernel_debug_tracer.h"

/* DebugFS file operations */
static ssize_t control_read(struct file *file, char __user *user_buf,
                           size_t count, loff_t *ppos);
static ssize_t control_write(struct file *file, const char __user *user_buf,
                            size_t count, loff_t *ppos);
static ssize_t breakpoints_read(struct file *file, char __user *user_buf,
                               size_t count, loff_t *ppos);
static ssize_t breakpoints_write(struct file *file, const char __user *user_buf,
                                size_t count, loff_t *ppos);
static ssize_t trace_data_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *ppos);
static ssize_t status_read(struct file *file, char __user *user_buf,
                          size_t count, loff_t *ppos);
static ssize_t config_read(struct file *file, char __user *user_buf,
                          size_t count, loff_t *ppos);
static ssize_t config_write(struct file *file, const char __user *user_buf,
                           size_t count, loff_t *ppos);

/* File operations structures */
static const struct file_operations control_fops = {
    .owner = THIS_MODULE,
    .read = control_read,
    .write = control_write,
    .llseek = default_llseek,
};

static const struct file_operations breakpoints_fops = {
    .owner = THIS_MODULE,
    .read = breakpoints_read,
    .write = breakpoints_write,
    .llseek = default_llseek,
};

static const struct file_operations trace_data_fops = {
    .owner = THIS_MODULE,
    .read = trace_data_read,
    .llseek = default_llseek,
};

static const struct file_operations status_fops = {
    .owner = THIS_MODULE,
    .read = status_read,
    .llseek = default_llseek,
};

static const struct file_operations config_fops = {
    .owner = THIS_MODULE,
    .read = config_read,
    .write = config_write,
    .llseek = default_llseek,
};

/**
 * debugfs_interface_init - Initialize the debugfs interface
 * 
 * Return: 0 on success, negative error code on failure
 */
int debugfs_interface_init(void)
{
    struct dentry *root_dir;
    
    pr_debug("DebugFS Interface: Initializing\n");
    
    /* Create root directory */
    root_dir = debugfs_create_dir("kernel_debug_tracer", NULL);
    if (IS_ERR(root_dir)) {
        pr_err("Failed to create debugfs root directory\n");
        return PTR_ERR(root_dir);
    }
    
    tracer_state.debugfs_root = root_dir;
    
    /* Create control interface */
    if (!debugfs_create_file("control", 0644, root_dir, NULL, &control_fops)) {
        pr_err("Failed to create control file\n");
        goto err_cleanup;
    }
    
    /* Create breakpoints interface */
    if (!debugfs_create_file("breakpoints", 0644, root_dir, NULL, &breakpoints_fops)) {
        pr_err("Failed to create breakpoints file\n");
        goto err_cleanup;
    }
    
    /* Create trace data interface */
    if (!debugfs_create_file("trace_data", 0444, root_dir, NULL, &trace_data_fops)) {
        pr_err("Failed to create trace_data file\n");
        goto err_cleanup;
    }
    
    /* Create status interface */
    if (!debugfs_create_file("status", 0444, root_dir, NULL, &status_fops)) {
        pr_err("Failed to create status file\n");
        goto err_cleanup;
    }
    
    /* Create config interface */
    if (!debugfs_create_file("config", 0644, root_dir, NULL, &config_fops)) {
        pr_err("Failed to create config file\n");
        goto err_cleanup;
    }
    
    pr_debug("DebugFS Interface: Initialization complete\n");
    pr_info("Debug interface available at /sys/kernel/debug/kernel_debug_tracer/\n");
    return 0;

err_cleanup:
    debugfs_remove_recursive(root_dir);
    tracer_state.debugfs_root = NULL;
    return -ENODEV;
}

/**
 * debugfs_interface_exit - Cleanup the debugfs interface
 */
void debugfs_interface_exit(void)
{
    pr_debug("DebugFS Interface: Shutting down\n");
    
    if (tracer_state.debugfs_root) {
        debugfs_remove_recursive(tracer_state.debugfs_root);
        tracer_state.debugfs_root = NULL;
    }
    
    pr_debug("DebugFS Interface: Shutdown complete\n");
}

/**
 * control_read - Read from control interface
 */
static ssize_t control_read(struct file *file, char __user *user_buf,
                           size_t count, loff_t *ppos)
{
    char buf[256];
    int len;
    
    len = snprintf(buf, sizeof(buf), 
                  "enabled: %s\n"
                  "target_module: %s\n"
                  "trace_function_calls: %s\n"
                  "trace_variable_changes: %s\n",
                  tracer_state.config.enabled ? "true" : "false",
                  tracer_state.config.target_module,
                  tracer_state.config.trace_function_calls ? "true" : "false",
                  tracer_state.config.trace_variable_changes ? "true" : "false");
    
    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/**
 * control_write - Write to control interface
 */
static ssize_t control_write(struct file *file, const char __user *user_buf,
                            size_t count, loff_t *ppos)
{
    char buf[256];
    char *cmd, *arg;
    
    if (count >= sizeof(buf))
        return -EINVAL;
    
    if (copy_from_user(buf, user_buf, count))
        return -EFAULT;
    
    buf[count] = '\0';
    
    /* Parse command */
    cmd = strim(buf);
    arg = strchr(cmd, ' ');
    if (arg) {
        *arg++ = '\0';
        arg = strim(arg);
    }
    
    if (strcmp(cmd, "enable") == 0) {
        tracer_state.config.enabled = true;
        pr_info("Debug tracing enabled\n");
    } else if (strcmp(cmd, "disable") == 0) {
        tracer_state.config.enabled = false;
        pr_info("Debug tracing disabled\n");
    } else if (strcmp(cmd, "clear") == 0) {
        data_collector_clear();
        pr_info("Debug events cleared\n");
    } else if (strcmp(cmd, "target") == 0 && arg) {
        strncpy(tracer_state.config.target_module, arg, MODULE_NAME_MAX - 1);
        tracer_state.config.target_module[MODULE_NAME_MAX - 1] = '\0';
        pr_info("Target module set to: %s\n", arg);
    } else {
        pr_err("Unknown command: %s\n", cmd);
        return -EINVAL;
    }
    
    return count;
}

/**
 * breakpoints_read - Read breakpoints list
 */
static ssize_t breakpoints_read(struct file *file, char __user *user_buf,
                               size_t count, loff_t *ppos)
{
    struct breakpoint_info *bp;
    char *buf;
    int len = 0, total_len = 0;
    unsigned long flags;
    ssize_t ret;
    
    buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    
    spin_lock_irqsave(&tracer_state.breakpoints_lock, flags);
    list_for_each_entry(bp, &tracer_state.breakpoints, list) {
        len = snprintf(buf + total_len, PAGE_SIZE - total_len,
                      "0x%lx %s:%d %s %s hits=%d\n",
                      bp->addr,
                      bp->source_file,
                      bp->line_number,
                      bp->function_name,
                      bp->enabled ? "enabled" : "disabled",
                      bp->hit_count);
        
        total_len += len;
        if (total_len >= PAGE_SIZE - 1)
            break;
    }
    spin_unlock_irqrestore(&tracer_state.breakpoints_lock, flags);
    
    ret = simple_read_from_buffer(user_buf, count, ppos, buf, total_len);
    kfree(buf);
    return ret;
}

/**
 * breakpoints_write - Add/remove breakpoints
 */
static ssize_t breakpoints_write(struct file *file, const char __user *user_buf,
                                size_t count, loff_t *ppos)
{
    char buf[256];
    char *cmd, *file_arg, *line_arg;
    int line_num;
    int ret;
    
    if (count >= sizeof(buf))
        return -EINVAL;
    
    if (copy_from_user(buf, user_buf, count))
        return -EFAULT;
    
    buf[count] = '\0';
    
    /* Parse command: "add filename:line" or "remove address" */
    cmd = strim(buf);
    
    if (strncmp(cmd, "add ", 4) == 0) {
        file_arg = cmd + 4;
        line_arg = strchr(file_arg, ':');
        if (!line_arg) {
            return -EINVAL;
        }
        
        *line_arg++ = '\0';
        if (kstrtoint(line_arg, 10, &line_num) != 0) {
            return -EINVAL;
        }
        
        ret = bp_manager_add_breakpoint(file_arg, line_num);
        if (ret) {
            return ret;
        }
        
        pr_info("Added breakpoint at %s:%d\n", file_arg, line_num);
    } else if (strncmp(cmd, "remove ", 7) == 0) {
        unsigned long addr;
        if (kstrtoul(cmd + 7, 16, &addr) != 0) {
            return -EINVAL;
        }
        
        ret = bp_manager_remove_breakpoint(addr);
        if (ret) {
            return ret;
        }
        
        pr_info("Removed breakpoint at 0x%lx\n", addr);
    } else {
        return -EINVAL;
    }
    
    return count;
}

/**
 * trace_data_read - Read trace data
 */
static ssize_t trace_data_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *ppos)
{
    struct debug_event **events;
    char *buf;
    int event_count = 0;
    int len = 0, total_len = 0;
    int i;
    ssize_t ret;
    
    /* Get events from data collector */
    if (data_collector_get_events((struct debug_event **)&events, &event_count, NULL) != 0) {
        return -EIO;
    }
    
    if (event_count == 0) {
        return simple_read_from_buffer(user_buf, count, ppos, "No events\n", 10);
    }
    
    buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        kfree(events);
        return -ENOMEM;
    }
    
    /* Format events */
    for (i = 0; i < event_count && total_len < PAGE_SIZE - 1; i++) {
        struct debug_event *event = events[i];
        
        len = snprintf(buf + total_len, PAGE_SIZE - total_len,
                      "[%lu] %s at 0x%lx pid=%d\n",
                      event->timestamp,
                      event->event_type,
                      event->trigger_addr,
                      event->pid);
        
        total_len += len;
    }
    
    ret = simple_read_from_buffer(user_buf, count, ppos, buf, total_len);
    
    /* Cleanup */
    for (i = 0; i < event_count; i++) {
        kfree(events[i]);
    }
    kfree(events);
    kfree(buf);
    
    return ret;
}

/**
 * status_read - Read system status
 */
static ssize_t status_read(struct file *file, char __user *user_buf,
                          size_t count, loff_t *ppos)
{
    char buf[512];
    int len;
    
    len = snprintf(buf, sizeof(buf),
                  "initialized: %s\n"
                  "enabled: %s\n"
                  "event_count: %d\n"
                  "max_events: %d\n"
                  "target_module: %s\n"
                  "stack_depth_limit: %d\n",
                  tracer_state.initialized ? "true" : "false",
                  tracer_state.config.enabled ? "true" : "false",
                  tracer_state.event_count,
                  tracer_state.config.max_events,
                  tracer_state.config.target_module,
                  tracer_state.config.stack_depth_limit);
    
    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/**
 * config_read - Read configuration
 */
static ssize_t config_read(struct file *file, char __user *user_buf,
                          size_t count, loff_t *ppos)
{
    char buf[512];
    int len;
    
    len = snprintf(buf, sizeof(buf),
                  "max_events=%d\n"
                  "stack_depth_limit=%d\n"
                  "trace_function_calls=%s\n"
                  "trace_variable_changes=%s\n"
                  "filter_mask=0x%lx\n",
                  tracer_state.config.max_events,
                  tracer_state.config.stack_depth_limit,
                  tracer_state.config.trace_function_calls ? "true" : "false",
                  tracer_state.config.trace_variable_changes ? "true" : "false",
                  tracer_state.config.filter_mask);
    
    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/**
 * config_write - Write configuration
 */
static ssize_t config_write(struct file *file, const char __user *user_buf,
                           size_t count, loff_t *ppos)
{
    char buf[256];
    char *key, *value;
    
    if (count >= sizeof(buf))
        return -EINVAL;
    
    if (copy_from_user(buf, user_buf, count))
        return -EFAULT;
    
    buf[count] = '\0';
    
    /* Parse key=value */
    key = strim(buf);
    value = strchr(key, '=');
    if (!value)
        return -EINVAL;
    
    *value++ = '\0';
    value = strim(value);
    
    if (strcmp(key, "max_events") == 0) {
        int val;
        if (kstrtoint(value, 10, &val) == 0 && val > 0) {
            tracer_state.config.max_events = val;
        }
    } else if (strcmp(key, "stack_depth_limit") == 0) {
        int val;
        if (kstrtoint(value, 10, &val) == 0 && val > 0 && val <= MAX_STACK_DEPTH) {
            tracer_state.config.stack_depth_limit = val;
        }
    } else if (strcmp(key, "trace_function_calls") == 0) {
        tracer_state.config.trace_function_calls = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "trace_variable_changes") == 0) {
        tracer_state.config.trace_variable_changes = (strcmp(value, "true") == 0);
    } else {
        return -EINVAL;
    }
    
    return count;
}