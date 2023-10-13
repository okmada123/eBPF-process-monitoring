# TODO

- [ ] the BPF program (in kernel) does not like having `char buff[PATH_MAX]` on stack - maybe move into a BPF map (using smaller buffer size for now)
- [ ] [open-tracking] when AT_FDCWD is used, is it possible to find out what the current working directory is?