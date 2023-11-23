# TODO

- [ ] the BPF program (in kernel) does not like having `char buff[PATH_MAX]` on stack - maybe move into a BPF map (using smaller buffer size for now)
- [ ] [open-tracking] when AT_FDCWD is used, is it possible to find out what the current working directory is?
    - check this https://stackoverflow.com/questions/1188757/retrieve-filename-from-file-descriptor-in-c
- [X] [API+Dashboard] - add 'color' in API response, and print the rows with this color in the dashboard
- [X] [API] - add config and use colors based on allowed paths/binaries, etc - from the config
- [X] [API] - add regex handling for 'connect' (these events use different fields, not 'path')
- [X] [connection-accept] - try to track `accept4` instead of `tcp_v4_do_rcv` - will it be possible to read the addresses from there? - Done, but can only read remote address (which is probably okay...)
- [ ] - refactor EVENT constants
- [X] [API] - add more granular connection rules - regexes handle this actually

Useful development tool: `bpftrace`

# Future work

- [ ] [connection-tracking] - add IPv6 support