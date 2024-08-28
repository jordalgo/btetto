# btetto

A tool that produces [Perfetto](https://perfetto.dev/) protobuf from formatted [bpftrace](https://github.com/bpftrace/bpftrace) output.

# Usage
```
$ sudo bpftrace my_script.bt -f json | ./btetto.py
Attached probes: 4
^C
Writing 149 events to trace file: bpftrace_trace.binpb
```

btetto.py produces a bpftrace_trace.binpb protobuf file, which can then be loaded into the [Perfetto UI](https://ui.perfetto.dev/).
