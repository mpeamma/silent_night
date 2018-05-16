echo "0x$(cat /proc/kallsyms | grep ' sys_call_table' | cut -d' ' -f1)"
