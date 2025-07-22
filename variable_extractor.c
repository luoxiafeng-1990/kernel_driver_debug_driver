/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Debug Tracer - Variable Extractor
 * 
 * This module extracts variable values from memory during debugging.
 * It handles local variables, global variables, and complex data types.
 */

#include "kernel_debug_tracer.h"

/* Static function declarations */
static int extract_register_variable(struct pt_regs *regs, int reg_num, 
                                   struct variable_value *var);
static int extract_stack_variable(struct pt_regs *regs, int offset, int size,
                                struct variable_value *var);
static int format_variable_value(struct variable_value *var);
static bool is_safe_memory_access(unsigned long addr, int size);

/**
 * variable_extractor_init - Initialize the variable extractor
 * 
 * Return: 0 on success, negative error code on failure
 */
int variable_extractor_init(void)
{
    pr_debug("Variable Extractor: Initializing\n");
    
    /* No specific initialization needed */
    
    pr_debug("Variable Extractor: Initialization complete\n");
    return 0;
}

/**
 * variable_extractor_exit - Cleanup the variable extractor
 */
void variable_extractor_exit(void)
{
    pr_debug("Variable Extractor: Shutting down\n");
    
    /* No specific cleanup needed */
    
    pr_debug("Variable Extractor: Shutdown complete\n");
}

/**
 * variable_extractor_get_local_vars - Extract local variables from current context
 * @regs: CPU registers
 * @function_name: Name of the current function
 * @vars: Pointer to array of variable values (allocated by this function)
 * @count: Pointer to store the number of variables found
 * 
 * Return: 0 on success, negative error code on failure
 */
int variable_extractor_get_local_vars(struct pt_regs *regs, 
                                     const char *function_name,
                                     struct variable_value **vars,
                                     int *count)
{
    struct variable_value *var_array;
    int var_count = 0;
    int i;
    
    if (!regs || !function_name || !vars || !count) {
        return -EINVAL;
    }
    
    pr_debug("Extracting local variables for function '%s'\n", function_name);
    
    /* TODO: Get variable information from DWARF debug info */
    /* For now, extract some common register-based variables */
    
    /* Allocate space for variables */
    var_array = kzalloc(sizeof(*var_array) * MAX_VARS_PER_EVENT, GFP_ATOMIC);
    if (!var_array) {
        return -ENOMEM;
    }
    
    /* Extract variables from registers (RISC-V64 calling convention) */
#ifdef CONFIG_RISCV
    /* Function arguments in a0-a7 registers */
    for (i = 0; i < 8 && var_count < MAX_VARS_PER_EVENT; i++) {
        struct variable_value *var = &var_array[var_count];
        
        snprintf(var->name, VAR_NAME_MAX, "arg%d", i);
        snprintf(var->type, TYPE_NAME_MAX, "unsigned long");
        var->size = sizeof(unsigned long);
        var->data = kzalloc(var->size, GFP_ATOMIC);
        
        if (var->data) {
            if (extract_register_variable(regs, 10 + i, var) == 0) {
                format_variable_value(var);
                var_count++;
            } else {
                kfree(var->data);
                var->data = NULL;
            }
        }
    }
#endif
    
    *vars = var_array;
    *count = var_count;
    
    pr_debug("Extracted %d local variables\n", var_count);
    return 0;
}

/**
 * variable_extractor_get_global_var - Extract a global variable value
 * @var_name: Name of the global variable
 * @var: Variable value structure to fill
 * 
 * Return: 0 on success, negative error code on failure
 */
int variable_extractor_get_global_var(const char *var_name,
                                     struct variable_value *var)
{
    unsigned long addr;
    
    if (!var_name || !var) {
        return -EINVAL;
    }
    
    pr_debug("Extracting global variable '%s'\n", var_name);
    
    /* TODO: Look up global variable address using symbol resolver */
    addr = symbol_resolver_name_to_addr(var_name);
    if (!addr) {
        pr_debug("Global variable '%s' not found\n", var_name);
        return -ENOENT;
    }
    
    /* TODO: Extract variable value from memory */
    strncpy(var->name, var_name, VAR_NAME_MAX - 1);
    var->name[VAR_NAME_MAX - 1] = '\0';
    
    /* For now, just mark as found but not extracted */
    snprintf(var->string_repr, VALUE_STR_MAX, "<global variable at 0x%lx>", addr);
    
    return 0;
}

/**
 * extract_register_variable - Extract variable value from CPU register
 * @regs: CPU registers
 * @reg_num: Register number (RISC-V convention)
 * @var: Variable structure to fill
 * 
 * Return: 0 on success, negative error code on failure
 */
static int extract_register_variable(struct pt_regs *regs, int reg_num, 
                                   struct variable_value *var)
{
    unsigned long value = 0;
    
    if (!regs || !var || !var->data) {
        return -EINVAL;
    }
    
#ifdef CONFIG_RISCV
    /* Extract value from RISC-V register */
    switch (reg_num) {
        case 10: value = regs->a0; break;  /* a0 */
        case 11: value = regs->a1; break;  /* a1 */
        case 12: value = regs->a2; break;  /* a2 */
        case 13: value = regs->a3; break;  /* a3 */
        case 14: value = regs->a4; break;  /* a4 */
        case 15: value = regs->a5; break;  /* a5 */
        case 16: value = regs->a6; break;  /* a6 */
        case 17: value = regs->a7; break;  /* a7 */
        case 2:  value = regs->sp; break;  /* sp */
        case 8:  value = regs->s0; break;  /* s0/fp */
        case 1:  value = regs->ra; break;  /* ra */
        default:
            pr_debug("Unsupported register number: %d\n", reg_num);
            return -EINVAL;
    }
#else
    /* Generic fallback */
    pr_debug("Register extraction not implemented for this architecture\n");
    return -ENOSYS;
#endif
    
    /* Copy value to variable data */
    memcpy(var->data, &value, sizeof(value));
    
    return 0;
}

/**
 * extract_stack_variable - Extract variable value from stack
 * @regs: CPU registers
 * @offset: Offset from stack pointer
 * @size: Size of variable in bytes
 * @var: Variable structure to fill
 * 
 * Return: 0 on success, negative error code on failure
 */
static int extract_stack_variable(struct pt_regs *regs, int offset, int size,
                                struct variable_value *var)
{
    unsigned long stack_addr;
    
    if (!regs || !var || !var->data || size <= 0 || size > MAX_VAR_SIZE) {
        return -EINVAL;
    }
    
#ifdef CONFIG_RISCV
    stack_addr = regs->sp + offset;
#else
    pr_debug("Stack variable extraction not implemented for this architecture\n");
    return -ENOSYS;
#endif
    
    /* Validate memory access */
    if (!is_safe_memory_access(stack_addr, size)) {
        pr_debug("Unsafe memory access at 0x%lx (size %d)\n", stack_addr, size);
        return -EFAULT;
    }
    
    /* Copy data from stack */
    if (copy_from_kernel_nofault(var->data, (void *)stack_addr, size)) {
        pr_debug("Failed to read from stack address 0x%lx\n", stack_addr);
        return -EFAULT;
    }
    
    var->size = size;
    return 0;
}

/**
 * format_variable_value - Format variable value as string
 * @var: Variable to format
 * 
 * Return: 0 on success, negative error code on failure
 */
static int format_variable_value(struct variable_value *var)
{
    if (!var || !var->data) {
        return -EINVAL;
    }
    
    /* Format based on type and size */
    if (var->size == sizeof(unsigned long)) {
        unsigned long value = *(unsigned long *)var->data;
        snprintf(var->string_repr, VALUE_STR_MAX, "0x%lx (%lu)", value, value);
    } else if (var->size == sizeof(unsigned int)) {
        unsigned int value = *(unsigned int *)var->data;
        snprintf(var->string_repr, VALUE_STR_MAX, "0x%x (%u)", value, value);
    } else if (var->size == sizeof(unsigned char)) {
        unsigned char value = *(unsigned char *)var->data;
        snprintf(var->string_repr, VALUE_STR_MAX, "0x%02x (%u)", value, value);
    } else {
        /* Generic hex dump for other sizes */
        int i, offset = 0;
        unsigned char *bytes = (unsigned char *)var->data;
        
        for (i = 0; i < var->size && offset < VALUE_STR_MAX - 3; i++) {
            offset += snprintf(var->string_repr + offset, 
                             VALUE_STR_MAX - offset, "%02x ", bytes[i]);
        }
        
        if (offset > 0 && var->string_repr[offset - 1] == ' ') {
            var->string_repr[offset - 1] = '\0';  /* Remove trailing space */
        }
    }
    
    return 0;
}

/**
 * is_safe_memory_access - Check if memory access is safe
 * @addr: Memory address to check
 * @size: Size of access
 * 
 * Return: true if safe, false otherwise
 */
static bool is_safe_memory_access(unsigned long addr, int size)
{
    /* Basic safety checks */
    if (!addr || size <= 0 || size > MAX_VAR_SIZE) {
        return false;
    }
    
    /* Check if address is valid kernel memory */
    if (!virt_addr_valid(addr) || !virt_addr_valid(addr + size - 1)) {
        return false;
    }
    
    return true;
}