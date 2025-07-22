/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - Call Stack Tracer
 * 
 * This module provides call stack tracing functionality for RISC-V64 architecture.
 * It captures and formats call stack information for debugging purposes.
 */

#include "kernel_debug_tracer.h"

/* RISC-V64 specific includes */
#ifdef CONFIG_RISCV
#include <asm/stacktrace.h>
#include <asm/ptrace.h>
#endif

/* Static function declarations */
static int capture_kernel_stack(struct call_stack *stack, struct pt_regs *regs);
static void format_stack_frame(struct call_frame *frame, char *buffer, int size);

/**
 * call_stack_tracer_init - Initialize the call stack tracer
 * 
 * Return: 0 on success, negative error code on failure
 */
int call_stack_tracer_init(void)
{
    pr_debug("Call Stack Tracer: Initializing\n");
    
    /* Verify architecture support */
#ifndef CONFIG_STACKTRACE
    pr_warn("Stack tracing not supported on this kernel configuration\n");
#endif
    
    pr_debug("Call Stack Tracer: Initialization complete\n");
    return 0;
}

/**
 * call_stack_tracer_exit - Cleanup the call stack tracer
 */
void call_stack_tracer_exit(void)
{
    pr_debug("Call Stack Tracer: Shutting down\n");
    
    /* No specific cleanup needed */
    
    pr_debug("Call Stack Tracer: Shutdown complete\n");
}

/**
 * call_stack_tracer_capture - Capture current call stack
 * @stack: Pointer to call_stack structure to fill
 * @regs: CPU registers (can be NULL for current context)
 * 
 * Return: 0 on success, negative error code on failure
 */
int call_stack_tracer_capture(struct call_stack *stack, struct pt_regs *regs)
{
    int ret = 0;
    
    if (!stack) {
        return -EINVAL;
    }
    
    /* Initialize stack structure */
    memset(stack, 0, sizeof(*stack));
    
    pr_debug("Capturing call stack\n");
    
    /* Capture kernel stack */
    ret = capture_kernel_stack(stack, regs);
    if (ret) {
        pr_debug("Failed to capture kernel stack: %d\n", ret);
        return ret;
    }
    
    pr_debug("Captured %d stack frames\n", stack->depth);
    return 0;
}

/**
 * call_stack_tracer_print - Print call stack to buffer
 * @stack: Call stack to print
 * @buffer: Output buffer
 * @size: Size of output buffer
 */
void call_stack_tracer_print(struct call_stack *stack, char *buffer, int size)
{
    int i, offset = 0;
    
    if (!stack || !buffer || size <= 0) {
        return;
    }
    
    offset += snprintf(buffer + offset, size - offset, 
                      "Call Stack (%d frames):\n", stack->depth);
    
    for (i = 0; i < stack->depth && offset < size - 1; i++) {
        offset += snprintf(buffer + offset, size - offset, 
                          "  #%d: ", i);
        
        format_stack_frame(&stack->frames[i], buffer + offset, size - offset);
        
        /* Find the length of what was just written */
        while (offset < size - 1 && buffer[offset] != '\0') {
            offset++;
        }
        
        if (offset < size - 1) {
            buffer[offset++] = '\n';
            buffer[offset] = '\0';
        }
    }
}

/**
 * capture_kernel_stack - Capture kernel call stack
 * @stack: Call stack structure to fill
 * @regs: CPU registers (can be NULL)
 * 
 * Return: 0 on success, negative error code on failure
 */
static int capture_kernel_stack(struct call_stack *stack, struct pt_regs *regs)
{
    unsigned long *frame_ptr;
    unsigned long return_addr;
    int depth = 0;
    
#ifdef CONFIG_RISCV
    /* RISC-V64 specific stack walking */
    if (regs) {
        frame_ptr = (unsigned long *)regs->s0;  /* Frame pointer */
        return_addr = regs->ra;                 /* Return address */
    } else {
        /* Current context */
        frame_ptr = (unsigned long *)__builtin_frame_address(0);
        return_addr = (unsigned long)__builtin_return_address(0);
    }
    
    /* Walk the stack frames */
    while (frame_ptr && depth < MAX_STACK_DEPTH) {
        /* Validate frame pointer */
        if (!virt_addr_valid((unsigned long)frame_ptr)) {
            break;
        }
        
        /* Fill frame information */
        stack->frames[depth].addr = return_addr;
        
        /* TODO: Resolve address to symbol information */
        snprintf(stack->frames[depth].function_name, FUNC_NAME_MAX, 
                "0x%lx", return_addr);
        snprintf(stack->frames[depth].file_name, PATH_MAX, "unknown");
        stack->frames[depth].line_number = 0;
        
        depth++;
        
        /* Move to next frame */
        if (frame_ptr[0] == 0) {
            break;  /* End of stack */
        }
        
        return_addr = frame_ptr[1];  /* Return address is at fp[1] */
        frame_ptr = (unsigned long *)frame_ptr[0];  /* Next frame at fp[0] */
    }
#else
    /* Generic stack capture using dump_stack functionality */
    pr_debug("Generic stack capture not implemented\n");
    
    /* Add at least current function */
    if (depth < MAX_STACK_DEPTH) {
        stack->frames[depth].addr = (unsigned long)__builtin_return_address(0);
        snprintf(stack->frames[depth].function_name, FUNC_NAME_MAX, 
                "current_function");
        snprintf(stack->frames[depth].file_name, PATH_MAX, "unknown");
        stack->frames[depth].line_number = 0;
        depth++;
    }
#endif
    
    stack->depth = depth;
    return 0;
}

/**
 * format_stack_frame - Format a single stack frame for display
 * @frame: Stack frame to format
 * @buffer: Output buffer
 * @size: Size of output buffer
 */
static void format_stack_frame(struct call_frame *frame, char *buffer, int size)
{
    if (!frame || !buffer || size <= 0) {
        return;
    }
    
    if (strlen(frame->function_name) > 0 && 
        strcmp(frame->function_name, "unknown") != 0) {
        snprintf(buffer, size, "%s+0x%lx", 
                frame->function_name, frame->addr);
    } else {
        snprintf(buffer, size, "0x%lx", frame->addr);
    }
    
    /* Add file and line information if available */
    if (strlen(frame->file_name) > 0 && 
        strcmp(frame->file_name, "unknown") != 0 && 
        frame->line_number > 0) {
        int len = strlen(buffer);
        snprintf(buffer + len, size - len, " (%s:%d)", 
                frame->file_name, frame->line_number);
    }
}