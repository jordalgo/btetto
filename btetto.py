#!/usr/bin/env python3.9

import json
import sys
import perfetto_trace_pb2

# TODOs
# - add support for changing the perf event name from cpu-clock
# - look into supporting dict_entries for debug annotations
# - add support for unit_multiplier

VALID_TRACE_DATA_TYPES = {"track_descriptor", "track_event"}
# bpftrace doesn't have a builtin to extract the process name
TRACK_DESCRIPTOR_NAMES = {"counter", "name", "thread_name"}
TRACK_DESCRIPTOR_UNIT_TYPES = {"unspecified", "time_ns", "count", "size_bytes"}
VALID_TRACE_EVENT_TYPES = {"BEGIN", "COUNTER", "END", "INSTANT"}

trusted_packet_sequence_id = 1
track_descriptor_uuid = 0
current_flow_id = 0
interned_data_id = 0
is_first_packet = True
is_first_perf_event = True

name_uuids = {}
pid_tid_uuids = {}
flow_name_ids = {}
string_ids = {}
call_stack_ids = {}

def get_string_id(s, id_obj, encode=False):
    global interned_data_id
    added = False
    if s not in string_ids:
        interned_data_id += 1
        string_ids[s] = interned_data_id
        added = True
        interned_string = id_obj.add()
        interned_string.iid = interned_data_id
        if encode:
            interned_string.str = str.encode(s)
        else:
            interned_string.name = s
    return (string_ids[s], added)
    
def add_stack_frame(packet, s):
    global interned_data_id
    str_id, added = get_string_id(s, packet.interned_data.function_names, True)
    if added:
        frame = packet.interned_data.frames.add()
        interned_data_id += 1
        frame.iid = interned_data_id
        frame.function_name_id = str_id
        frame.mapping_id = 1
        return interned_data_id
    return str_id + 1

def add_call_stack(packet, stack):
    global interned_data_id
    stack_ids = []
    for x in stack:
        stack_ids.append(add_stack_frame(packet, x))
    # lists aren't hashable but tuples are
    stack_ids_tuple = tuple(stack_ids)
    cs_id = call_stack_ids.get(stack_ids_tuple)
    if cs_id is None:
        interned_data_id += 1
        cs_id = interned_data_id
        call_stack_ids[stack_ids_tuple] = cs_id        
        call_stack = packet.interned_data.callstacks.add()
        call_stack.iid = cs_id
        for x in reversed(stack_ids):
            call_stack.frame_ids.append(x)
        current_packet = None
    return cs_id

def gen_uuid():
    global track_descriptor_uuid
    track_descriptor_uuid += 1
    return track_descriptor_uuid
    
def gen_flow_id():
    global current_flow_id
    current_flow_id += 1
    return current_flow_id
    
def get_flow_id_for_name(name):
    if name in flow_name_ids:
        return flow_name_ids[name]
    return None 
    
def get_uuid_for_name(name):
    if name in name_uuids:
        return name_uuids[name]
    return None
    
def get_uuid_for_pid_tid(pid, tid):
    if pid in pid_tid_uuids:
        return pid_tid_uuids[pid].get(tid)
    return None
    
def set_sequence_flags(packet):
    global is_first_packet
    if is_first_packet:
        packet.first_packet_on_sequence = True
        packet.previous_packet_dropped = True
        packet.sequence_flags = perfetto_trace_pb2.TracePacket.SequenceFlags.SEQ_INCREMENTAL_STATE_CLEARED | perfetto_trace_pb2.TracePacket.SequenceFlags.SEQ_NEEDS_INCREMENTAL_STATE        
        is_first_packet = False
    else:
        packet.sequence_flags = perfetto_trace_pb2.TracePacket.SequenceFlags.SEQ_NEEDS_INCREMENTAL_STATE
    
def parse_stack_str(stack):
    stack_arr = stack.split("\n")
    del stack_arr[0]
    del stack_arr[-1]
    cleaned_stack = []
    for x in stack_arr:
        cleaned_stack.append(x.strip())
    return cleaned_stack

# If there is a second stack it's always the user stack
def process_call_stacks(packet, stack1str, stack2str=None):
    stack1 = parse_stack_str(stack1str)
    if (len(stack1) == 0):
        return None
    if stack2str:
        stack2 = parse_stack_str(stack2str)
        return add_call_stack(packet, stack1 + stack2)
    return add_call_stack(packet, stack1)

# print(("perf_sample", "ts", nsecs, "pid", pid, "tid", tid, "kstack", kstack, "ustack", ustack));
def add_perf_sample(trace, data, data_len):
    global is_first_packet
    global is_first_perf_event
    if data_len < 7:
        print(f"Error: expected at least 7 fields for track event, got {data_len}")
        exit(1)
    
    x = 1
    event = {}
    while (x < data_len):
        event[data[x]] = data[x+1]
        x += 2
        
    if "ts" not in event:
        print("Error: perf sample must have a timestamp")
        exit(1)

    if "pid" in event and "tid" in event:
        if get_uuid_for_pid_tid(event["pid"], event["tid"]) is None:
            # Track descriptor doesn't exist, let's make one
            add_track_descriptor_thread_impl(trace, event["pid"], event["tid"], event.get("thread_name", "unknown"))
    else:
        print("Error: perf sample must have a pid and a tid")
        exit(1)
        
    packet = trace.packet.add()
    packet.trusted_packet_sequence_id = 1 
    packet.timestamp = event["ts"]
    
    packet.perf_sample.cpu_mode = perfetto_trace_pb2.Profiling.CpuMode.MODE_USER
    
    set_sequence_flags(packet)
    
    if is_first_perf_event:
        dummy_mapping = packet.interned_data.mappings.add()
        dummy_mapping.iid = 1
        is_first_perf_event = False
    
    packet.perf_sample.pid = event["pid"]
    packet.perf_sample.tid = event["tid"]
    
    if "cpu" in event:
        packet.perf_sample.cpu = event["cpu"]
        # packet.perf_sample.timebase_count = event.get("count", 1)
    
    callstack_iid = None
    
    if "kstack" in event:
        if "ustack" in event:
            callstack_iid = process_call_stacks(packet, event["kstack"], event["ustack"])
        else:
            callstack_iid = process_call_stacks(packet, event["kstack"])
    elif "ustack" in event:
        callstack_iid = process_call_stacks(packet, event["ustack"])
        
    if callstack_iid:
        packet.perf_sample.callstack_iid = callstack_iid

# Example valid track event tuple:
# print(("track_event", "name", "page_fault_user", "type", "BEGIN", "ts", $start / 1000, "pid", pid, "tid", tid, "thread_name", comm));
# print(("track_event", "name", "page_fault_user", "type", "INSTANT", "ts", $start / 1000, "pid", pid, "tid", tid, "thread_name", comm));
# print(("track_event", "name", "page_fault_user", "type", "COUNTER", "ts", $start / 1000, "track_name", "Number of User Page Faults", "counter_value", @c));
# print(("track_event", "name", "page_fault_user", "type", "BEGIN", "ts", $start, "pid", pid, "tid", tid, "thread_name", comm, "__a_bananas", 10, "__a_greeting", "hello"));
def add_track_event(trace, data, data_len):
    global is_first_packet
    if data_len < 7:
        print(f"Error: expected at least 7 fields for track event, got {data_len}")
        exit(1)
    
    x = 1
    event = {}
    while (x < data_len):
        event[data[x]] = data[x+1]
        x += 2
        
    if "name" not in event:
        print("Error: track event must have a name")
        exit(1)
        
    if "type" not in event or event["type"] not in VALID_TRACE_EVENT_TYPES:
        print(f"Error: track event must have a valid type: {VALID_TRACE_EVENT_TYPES}")
        exit(1)
        
    if "ts" not in event:
        print("Error: track event must have a timestamp")
        exit(1)
        
    event_type = event["type"]
    uuid = 0

    if "track_name" in event:
        uuid = get_uuid_for_name(event["track_name"])
        if uuid is None:
            print(f"Error: track name {event['track_name']} not found in track descriptors. You must emit a track_descriptor tuple for each track_name track_event. Skipping")
            return
    elif "pid" in event and "tid" in event:
        uuid = get_uuid_for_pid_tid(event["pid"], event["tid"])
        if uuid is None:
            # Track descriptor doesn't exist, let's make one
            uuid = add_track_descriptor_thread_impl(trace, event["pid"], event["tid"], event.get("thread_name", "unknown"))
    else:
        print("Error: track event must have either a pid/tid or a track_name")
        exit(1)
        
    if event_type == "COUNTER":
        if "track_name" not in event or "counter_value" not in event:
            print("Error: counter events need a 'track_name' and a 'counter_value'")
            exit(1)
            
        
    packet = trace.packet.add()
    packet.trusted_packet_sequence_id = 1
    packet.track_event.track_uuid = uuid
    
    set_sequence_flags(packet)
    
    packet.track_event.name_iid = get_string_id(event["name"], packet.interned_data.event_names)[0]
    packet.timestamp = event["ts"]
    
    event_type = event["type"]
    
    if event_type == "BEGIN":
        packet.track_event.type = perfetto_trace_pb2.TrackEvent.Type.TYPE_SLICE_BEGIN
    elif event_type == "END":
        packet.track_event.type = perfetto_trace_pb2.TrackEvent.Type.TYPE_SLICE_END
    elif event_type == "INSTANT":
        packet.track_event.type = perfetto_trace_pb2.TrackEvent.Type.TYPE_INSTANT
    elif event_type == "COUNTER":
        packet.track_event.type = perfetto_trace_pb2.TrackEvent.Type.TYPE_COUNTER
        packet.track_event.counter_value = event["counter_value"]
        
    if event_type != "COUNTER":
        for key, val in event.items():
            if key.startswith("__a_"):
                annotation = packet.track_event.debug_annotations.add()
                annotation.name_iid = get_string_id(key[4:], packet.interned_data.debug_annotation_names)[0]
                if isinstance(val, int):
                    annotation.int_value = val
                else:
                    annotation.string_value_iid = get_string_id(str(val), packet.interned_data.debug_annotation_string_values, True)[0]
            if key == "flow_name":
                flow_name = str(val)
                flow_id = get_flow_id_for_name(flow_name)
                if flow_id is None:
                    flow_id = gen_flow_id()
                    flow_name_ids[flow_name] = flow_id
                packet.track_event.flow_ids.append(flow_id)
        
def add_track_descriptor_name(trace, data, data_len):
    if data_len != 3 and data_len != 5:
        print(f"Error: expected 3 or 5 fields for track descriptor name, got {data_len}")
        exit(1)
    
    name = data[2]
        
    if get_uuid_for_name(name) is not None:
        # Already have this track descriptor, no need to re-add it
        return
        
    packet = trace.packet.add()
    packet.track_descriptor.name = name
    
    uuid = gen_uuid()
    name_uuids[name] = uuid
    packet.track_descriptor.uuid = uuid
    
    if data_len == 5:
        if data[3] != "parent":
            print(f"Error: expected the 4th field to be 'parent'. Got {data[3]}")
            exit(1)
        parent_uuid = get_uuid_for_name(data[4])
        if parent_uuid is None:
            print(f"Error: can't find track descriptor with name: {data[4]}")
            exit(1)
        packet.track_descriptor.parent_uuid = parent_uuid
        
    
def add_track_descriptor_thread_impl(trace, pid, tid, thread_name):
    packet = trace.packet.add()
    
    uuid = gen_uuid()
    if pid not in pid_tid_uuids:
        pid_tid_uuids[pid] = {}
    pid_tid_uuids[pid][tid] = uuid
    packet.track_descriptor.uuid = uuid
        
    packet.track_descriptor.thread.pid = pid
    packet.track_descriptor.thread.tid = tid
    packet.track_descriptor.thread.thread_name = thread_name
    
    return uuid
    
def add_track_descriptor_thread(trace, data, data_len):
    if data_len != 7:
        print(f"Error: expected 7 fields for track descriptor thread, got {data_len}")
        exit(1)
        
    thread_name = data[2]
        
    if data[3] != "pid":
        print(f"Error: expected the 4th field to be 'pid' got {data[3]}")
        exit(1)
        
    if data[5] != "tid":
        print(f"Error: expected 6th field to be 'tid' got {data[5]}")
        exit(1)
        
    if get_uuid_for_pid_tid(data[4], data[6]) is not None:
        # Already have this track descriptor, no need to re-add it
        return
        
    add_track_descriptor_thread_impl(trace, data[4], data[6], thread_name)
    
def add_track_descriptor_counter(trace, data, data_len):
    if data_len != 5:
        print(f"Error: expected 5 fields for track descriptor conter, got {data_len}")
        exit(1)
        
    name = data[2]
        
    if get_uuid_for_name(name) is not None:
        # Already have this track descriptor, no need to re-add it
        return
    
    packet = trace.packet.add()
    packet.track_descriptor.name = name
    uuid = gen_uuid()
    name_uuids[name] = uuid
    packet.track_descriptor.uuid = uuid
    
    if data[3] != "unit":
        print(f"Error: expected the 4th field to be 'unit' got {data[3]}")
        exit(1)
    
    unit = data[4]
    
    if unit == "unspecified":
        packet.track_descriptor.counter.unit = perfetto_trace_pb2.CounterDescriptor.Unit.UNIT_UNSPECIFIED
    elif unit == "count":
        packet.track_descriptor.counter.unit = perfetto_trace_pb2.CounterDescriptor.Unit.UNIT_COUNT
    elif unit == "size_bytes":
        packet.track_descriptor.counter.unit = perfetto_trace_pb2.CounterDescriptor.Unit.UNIT_SIZE_BYTES
    elif unit == "time_ns":
        packet.track_descriptor.counter.unit = perfetto_trace_pb2.CounterDescriptor.Unit.UNIT_TIME_NS
    else:
        print(f"Error: counter unit must be one of: {TRACK_DESCRIPTOR_UNIT_TYPES}. Got {unit}")

        
# Valid track descriptor tuples
# print(("track_descriptor", "thread_name", comm, "pid", pid, "tid", tid));
# print(("track_descriptor", "name", "my custom track", "parent", "Top Parent"));
# print(("track_descriptor", "counter", "counter name", "unit", "count"));
def add_track_descriptor(trace, data, data_len):
    x = 1
    
    descriptor_type = data[1]
    
    if descriptor_type == "name":
        add_track_descriptor_name(trace, data, data_len)
    elif descriptor_type == "thread_name":
        add_track_descriptor_thread(trace, data, data_len)
    elif descriptor_type == "counter":
        add_track_descriptor_counter(trace, data, data_len)
    else:
        print(f"Error: unexpected track descriptor type: {data[1]}. Valid types are: {TRACK_DESCRIPTOR_NAMES}")
        exit(1)
            
def parse_raw_data(data, trace):
    data_len = len(data)
    
    if data_len == 0:
        return
    
    if (data_len - 1) % 2 != 0:
        print("Error: There should be two fields for each entry: the name and the value. Excluding the first field which is the event type.")
        exit(1)    
    
    data_type = data[0]
    
    if data_type == "track_descriptor":
        add_track_descriptor(trace, data, data_len)
    elif data_type == "track_event":
        add_track_event(trace, data, data_len)
    elif data_type == "perf_sample":
        add_perf_sample(trace, data, data_len)
    else:
        print(f"Error: first field ({data_type}) is not a valid trace data type. Valid types are: {VALID_TRACE_DATA_TYPES}")
        exit(1)
        
        
def write_protobuf_trace_file(trace):
    with open('bpftrace_trace.binpb', 'wb') as f:
        f.write(trace.SerializeToString())
    
def main():
    trace = perfetto_trace_pb2.Trace()
    lines_processed = 0
    
    config_packet = trace.packet.add()
    # ds = config_packet.trace_config.data_sources.add()
    # ds.config.perf_event_config.timebase.frequency = 99
    # ds.config.perf_event_config.timebase.counter = perfetto_trace_pb2.PerfEvents.Counter.HW_CPU_CYCLES
    # ds.config.perf_event_config.timebase.timestamp_clock = perfetto_trace_pb2.PerfEvents.PerfClock.PERF_CLOCK_BOOTTIME

    try:
    
        # use stdin if it's full                                                        
        if not sys.stdin.isatty():
            input_stream = sys.stdin
        # otherwise, read the given filename                                            
        else:
            try:
                input_filename = sys.argv[1]
            except IndexError:
                message = 'need filename as first argument if stdin is not full'
                raise IndexError(message)
            else:
                input_stream = open(input_filename, 'rU')        
                

        for line in input_stream:
            json_line = json.loads(line)
            bt_type = json_line["type"]
            
            # Remove this when bpftrace automatically outputs this info
            if bt_type == "attached_probes":
                num_probes = json_line["data"]["probes"]
                print(f"Attached probes: {num_probes}")
            elif bt_type == "value":
                parse_raw_data(json_line["data"], trace)
                lines_processed += 1
                
        write_protobuf_trace_file(trace)
                
    except KeyboardInterrupt:
        print(f"\nWriting {lines_processed} events to trace file: bpftrace_trace.binpb")
        write_protobuf_trace_file(trace)
            
    
if __name__ == "__main__":
    main()