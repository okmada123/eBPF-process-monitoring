# TODO

- [ ] the BPF program (in kernel) does not like having `char buff[PATH_MAX]` on stack - maybe move into a BPF map (using smaller buffer size for now)
- [ ] [open-tracking] when AT_FDCWD is used, is it possible to find out what the current working directory is?
    - check this https://stackoverflow.com/questions/1188757/retrieve-filename-from-file-descriptor-in-c
- [X] [API+Dashboard] - add 'color' in API response, and print the rows with this color in the dashboard
- [ ] [API] - add config and use colors based on allowed paths/binaries, etc - from the config

Useful development tool: `bpftrace`
