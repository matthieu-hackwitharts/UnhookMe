# UnhookMe

UnhookMe is a universal "unhooker", which can unhook the Nt/Zw api of your choice, or all of them depending on your need.

# How it works

UnhookMe works by creating a suspended process (avoid being hooked), and by parsing its EAT to retrieve wanted Nt apis. Then it will patch them with the right opcodes of a traditionnal syscall. It has the advantage to be more precise and selective compare to others ways, as it can easily retrieve a particular syscall.\
It comes in the form of a dll and a cna script (Cobaltstrike), to be used in post operation to remove the hooks placed on the current beacon. It uses a reflective injection to inject itself into the current beacon process.

# How to use

There are two main components in this project:<br>
- **unhook_me.cna** : The cna module for Cobaltstrike, you should import it to use unhook_me command (Script Manager)
- **unhook_me dll** : The main project and code for the unhook_me dll, **no releases will be available**.

Detailed usage :

```unhook_me NtCreateUserProcess (your function)```\
```unhook_me``` (Default will unhook all functions)

<br>

The reflective dll injection was pulled from : https://github.com/stephenfewer/ReflectiveDLLInjection
