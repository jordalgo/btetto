# btetto

A tool that produces [Perfetto](https://perfetto.dev/) protobuf from formatted [bpftrace](https://github.com/bpftrace/bpftrace) output.

# Usage
```
$ sudo bpftrace my_script.bt -f json | ./btetto
Attached probes: 4
^C
Writing 149 events to trace file: bpftrace_trace.binpb
```

btetto.py produces a bpftrace_trace.binpb protobuf file, which can then be loaded into the [Perfetto UI](https://ui.perfetto.dev/).

# bpftrace Output Format
The print output from bpftrace should be tuples (in JSON format e.g. `-f json`) where the first item in the tuple is the event type and the rest of the items are key/value tuples.

## Event Types
- track_event
- track_descriptor
- call_stack

## Track Events (Spans)
These have three types: "BEGIN", "END", and "COUNTER" where "ts" is the timestamp of when these events occurred.

**Required Fields**:
- name
- ts
- type

**Optional Fields**:
- pid
- thread_name
- tid
- track_name

If the field is not listed above it will get logged as an annotation on the event like "bananas" and "greeting" below.

```
print(("track_event", ("name", "page_fault_user"), ("type", "BEGIN"), ("ts", $start), ("pid", pid), ("tid", tid), ("thread_name", comm), ("bananas", 10), ("greeting", "hello")));
        
print(("track_event", ("name", "page_fault_user"), ("type", "END"), ("ts", nsecs), ("pid", pid), ("tid", tid), ("thread_name", comm)));
```

## Track Descriptor
These define track names in the Perfetto UI. At the moment only "track_event" event types can utilize custom tracks and to do that they need to set the track name in your track event (above) e.g. `(..., ("track_name", "Sub Parent A"))`.

There are three different types of descriptors:
- name
- thread_name
- counter

### name
These are generic descriptors and can specify a "parent".

```
print(("track_descriptor", ("name", "Top Parent")));
print(("track_descriptor", ("name", "Sub Parent A"), ("parent", "Top Parent")));
```

### thread_name
These are specifically for naming pid/tid tracks and require both the "pid" and "tid" pairs. These will get added automatically if you have pid, tid, and thread_name in your track_event.

```
print(("track_descriptor", ("thread_name", comm), ("pid", pid), ("tid", tid)));
```

### counter
These are for "COUNTER" type track events and require a "unit", which can be:
- unspecified
- count
- size_bytes
- time_ns

```
print(("track_descriptor", ("counter", "Donut Counts"), ("unit", "count")));
```

## Call Stack Sample
These are for logging call stacks (kernel, user, or both) at specific points in time. They do not have durations.

**Required Fields**:
- pid
- tid
- ts
- kstack or ustack (or both)

**Optional Fields**:
- thread_name

```
print(("call_stack", ("ts", nsecs), ("pid", pid), ("tid", tid), ("thread_name", comm), ("kstack", kstack), ("ustack", ustack)));
```
