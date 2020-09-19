

# Options

You can execute `pointers` command without any parameters to see help below:

```
pointers [show [<start_pc> <end_pc>]] 
         [(to | to2) <address> [<start_pc> <end_pc>]]
```

# Finding all pointers

The option `show` shows all pointers in selected memory area. 

# Finding pointers and multi-level pointers to specific value

Options `to` and `to2` searches pointed values and shows relevant pointer information. Like `show` you can specify a memory area for searching pointers or leave it to plug-in to find current address space.  
