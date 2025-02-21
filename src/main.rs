use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self};

use serde_json::Value;

mod protos;
mod util;

use protobuf::Message;
use protos::protos_gen::perfetto_bpftrace::{
    counter_descriptor, debug_annotation, profiling, trace_packet, track_descriptor, track_event,
    Callstack, CounterDescriptor, DebugAnnotation, DebugAnnotationName, EventName, Frame,
    InternedData, InternedString, LogMessage, LogMessageBody, Mapping, PerfSample,
    ThreadDescriptor, Trace, TracePacket, TrackDescriptor, TrackEvent,
};

// cargo build && sudo bpftrace ~/jordan.bt -f json | ./target/debug/btetto

struct Ids {
    call_stack_ids: HashMap<Vec<u64>, u64>,
    flow_name_ids: HashMap<String, u64>,
    name_uuids: HashMap<String, u64>,
    pid_tid_uuids: HashMap<u64, HashMap<u64, u64>>,
    string_ids: HashMap<String, u64>,
    interned_data_id: u64,
}

static mut IS_FIRST_PACKET: bool = true;
static mut IS_FIRST_CALL_SAMPLE: bool = true;
static mut IS_TRACE_DONE: bool = false;
static mut TRACK_DESCRIPTOR_UUID: u64 = 1;
static mut FLOW_UUID: u64 = 1;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut trace = Trace::new();
    let mut ids = Ids {
        call_stack_ids: HashMap::new(),
        flow_name_ids: HashMap::new(),
        name_uuids: HashMap::new(),
        pid_tid_uuids: HashMap::new(),
        string_ids: HashMap::new(),
        interned_data_id: 1,
    };

    let packet = TracePacket::new();
    trace.packet.push(packet);

    let args_len = args.len();
    if args_len > 2 {
        panic!("btetto only supports one argument, an optional filename.");
    } else if args_len == 2 {
        if let Ok(lines) = util::read_lines(args[1].clone()) {
            for line in lines.flatten() {
                let parse_json_line = serde_json::from_str(&line);
                if parse_json_line.is_err() {
                    panic!("Error parsing json line {}", &line);
                }
                let json_line: Value = parse_json_line.unwrap();
                let out_type = &json_line["type"];
                if out_type == "value" {
                    parse_raw_data(&mut trace, &json_line["data"], &mut ids);
                }
            }
        } else {
            panic!("Could not read file {}", args[1].clone());
        }
    } else {
        ctrlc::set_handler(|| unsafe {
            IS_TRACE_DONE = true;
        })
        .expect("Error setting Ctrl-C handler");

        let mut input = String::new();
        loop {
            unsafe {
                if IS_TRACE_DONE {
                    break;
                }
            }

            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");
            if input.is_empty() {
                break;
            }
            let parse_json_line = serde_json::from_str(&input);
            if parse_json_line.is_err() {
                unsafe {
                    if !IS_TRACE_DONE {
                        println!("Error parsing json line {}", input.clone());
                    }
                }
                break;
            }
            let json_line: Value = parse_json_line.unwrap();
            let out_type = &json_line["type"];
            if out_type == "attached_probes" {
                let num_probes = &json_line["data"]["probes"];
                println!("Attaching {} probes...", num_probes);
            } else if out_type == "value" {
                parse_raw_data(&mut trace, &json_line["data"], &mut ids);
            }
            input.clear();
        }
    }

    println!(
        "Writing {} events to trace file: bpftrace_trace.binpb",
        trace.packet.len()
    );

    let out_bytes: Vec<u8> = trace.write_to_bytes().unwrap();

    fs::write("bpftrace_trace.binpb", out_bytes).expect("Could not write Perfetto protobuf file");
}

fn parse_raw_data(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    assert!(data.is_array(), "Expecting data to be a array.");

    if data.as_array().unwrap().len() == 0 {
        return;
    }

    let data_type = &data[0];

    if data_type == "track_event" {
        add_track_event(trace, &data, ids);
    } else if data_type == "call_stack" {
        add_call_stack_sample(trace, &data, ids);
    } else if data_type == "stdout" {
        println!("{}", data[1].as_str().unwrap());
    } else {
        panic!("The first field is not a valid trace data type");
    }
}

fn add_track_descriptor_name(
    track_name: &str,
    parent_name: Option<&str>,
    trace: &mut Trace,
    ids: &mut Ids,
) -> u64 {
    let full_name;
    if parent_name.is_some() {
        let parent = parent_name.unwrap();
        full_name = format!("{parent}/{track_name}");
    } else {
        full_name = track_name.to_string();
    }

    let maybe_uuid = get_uuid_for_name(&full_name, &ids);
    if maybe_uuid.is_some() {
        return maybe_uuid.unwrap().clone();
    }

    let uuid = gen_uuid();
    ids.name_uuids.insert(full_name.to_string(), uuid.clone());

    let mut packet = TracePacket::new();
    let mut track_descriptor = TrackDescriptor::new();
    track_descriptor.static_or_dynamic_name = Some(track_descriptor::Static_or_dynamic_name::Name(
        track_name.to_string(),
    ));
    track_descriptor.uuid = Some(uuid);

    if parent_name.is_some() {
        let mut parent_uuid = get_uuid_for_name(&parent_name.unwrap(), &ids);
        if parent_uuid.is_none() {
            parent_uuid = Some(add_track_descriptor_name(
                parent_name.unwrap(),
                None,
                trace,
                ids,
            ));
        }
        track_descriptor.parent_uuid = parent_uuid;
    }

    packet.data = Some(trace_packet::Data::TrackDescriptor(track_descriptor));
    trace.packet.push(packet);

    return uuid;
}

fn add_track_descriptor_counter(
    counter_name: &str,
    unit: Option<&str>,
    trace: &mut Trace,
    ids: &mut Ids,
) -> u64 {
    let maybe_uuid = get_uuid_for_name(&counter_name, &ids);
    if maybe_uuid.is_some() {
        // Already have this track descriptor, no need to re-add it
        return maybe_uuid.unwrap();
    }

    let uuid = gen_uuid();
    ids.name_uuids
        .insert(counter_name.to_string(), uuid.clone());

    let mut packet = TracePacket::new();
    let mut track_descriptor = TrackDescriptor::new();
    track_descriptor.static_or_dynamic_name = Some(track_descriptor::Static_or_dynamic_name::Name(
        counter_name.to_string(),
    ));
    track_descriptor.uuid = Some(uuid);

    let mut counter_descriptor = CounterDescriptor::new();

    // Count is the default
    if unit.is_some() {
        match unit.unwrap() {
            "unspecified" => {
                counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_UNSPECIFIED.into())
            }
            "count" => counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_COUNT.into()),
            "sized_bytes" => {
                counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_SIZE_BYTES.into())
            }
            "time_ns" => {
                counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_TIME_NS.into())
            }
            _ => panic!("Error: Unknown unit type {}", unit.unwrap()),
        }
    } else {
        counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_COUNT.into());
    }

    track_descriptor.counter = Some(counter_descriptor).into();
    packet.data = Some(trace_packet::Data::TrackDescriptor(track_descriptor));
    trace.packet.push(packet);

    return uuid;
}

// Example track events
// print(("track_event", ("name", "page_fault_user"), ("type", "BEGIN"), ("ts", $start), ("track_name", "Sub Parent A")));
// print(("track_event", ("name", "page_fault_user"), ("type", "END"), ("ts", nsecs), ("track_name", "Sub Parent A")));
// print(("track_event", ("name", "page_fault_user"), ("type", "BEGIN"), ("ts", $start), ("pid", pid), ("tid", tid), ("thread_name", comm), ("bananas", 10), ("greeting", "hello"), ("log", ("WARN", "this is my log message"))));
fn add_track_event(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    let mut event = HashMap::new();

    for i in 1..data.as_array().unwrap().len() {
        let pair = &data[i];
        assert!(
            pair.is_array() && pair.as_array().unwrap().len() == 2,
            "Expecting key/value tuples. Found {pair}"
        );
        let key = &pair[0];
        assert!(key.is_string(), "Expecting key to be a string. Found {key}");
        // do these have to be clones?
        event.insert(key.as_str().unwrap(), pair[1].clone());
    }

    util::validate_track_event(&event);

    let event_type = event["type"].as_str().unwrap();

    let mut track_uuid: Option<u64>;

    if event.contains_key("track") {
        let track_name = if event["track"].is_number() { event["track"].as_u64().unwrap().to_string() } else { event["track"].as_str().unwrap().to_string() };

        if event_type == "COUNTER" {
            if event.contains_key("unit") {
                track_uuid = Some(add_track_descriptor_counter(
                    &track_name,
                    event["unit"].as_str(),
                    trace,
                    ids,
                ));
            } else {
                track_uuid = Some(add_track_descriptor_counter(&track_name, None, trace, ids));
            }
        } else if event.contains_key("track_parent") {
            let track_parent = if event["track_parent"].is_number() { event["track_parent"].as_u64().unwrap().to_string() } else { event["track_parent"].as_str().unwrap().to_string() };
            track_uuid = Some(add_track_descriptor_name(
                &track_name,
                Some(&track_parent),
                trace,
                ids,
            ));
        } else {
            track_uuid = Some(add_track_descriptor_name(&track_name, None, trace, ids));
        }
    } else if event.contains_key("pid") && event.contains_key("tid") {
        let pid = event["pid"].as_u64().unwrap();
        let tid = event["tid"].as_u64().unwrap();
        track_uuid = get_uuid_for_pid_tid(&pid, &tid, &ids);
        if track_uuid.is_none() {
            let thread_name = if event.contains_key("thread_name") {
                event["thread_name"].as_str()
            } else {
                None
            };
            // Track descriptor doesn't exist, let's make one
            track_uuid = Some(add_track_descriptor_thread(
                trace,
                &pid,
                &tid,
                thread_name,
                ids,
            ))
        }
    } else {
        panic!("Error: track event must have either a pid and tid or a track");
    }

    let mut packet = TracePacket::new();
    packet.optional_trusted_packet_sequence_id =
        Some(trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(1));

    let mut track_event = TrackEvent::new();
    track_event.track_uuid = track_uuid;

    set_sequence_flags(&mut packet);

    let mut interned_data = InternedData::new();
    let event_name = event["name"].as_str().unwrap();
    let string_id_pair = get_string_id(event_name, ids);

    if string_id_pair.1 {
        let mut en = EventName::new();
        en.iid = Some(string_id_pair.0);
        en.name = Some(event_name.to_string());
        interned_data.event_names.push(en);
    }

    track_event.name_field = Some(track_event::Name_field::NameIid(string_id_pair.0));

    packet.timestamp = Some(event["ts"].as_u64().unwrap());

    track_event.type_ = Some(util::get_track_event_type(event_type).into());

    if event_type == "COUNTER" {
        track_event.counter_value_field = Some(track_event::Counter_value_field::CounterValue(
            event["counter_value"].as_i64().unwrap(),
        ));
    }

    if event.contains_key("log") {
        assert!(
            event["log"].is_array(),
            "Error: log tuple value must be another tuple e.g. ('log', ('WARN', 'my log message'))"
        );
        let log_val = event["log"].as_array().unwrap();
        let string_id_pair = get_string_id(log_val[1].as_str().unwrap(), ids);
        let body_iid;
        if string_id_pair.1 {
            ids.interned_data_id += 1;
            let mut log_message_body = LogMessageBody::new();
            log_message_body.iid = Some(ids.interned_data_id);
            log_message_body.body = Some(log_val[1].as_str().unwrap().to_string());
            interned_data.log_message_body.push(log_message_body);
            body_iid = ids.interned_data_id;
        } else {
            body_iid = string_id_pair.0 + 1;
        }
        let mut log_message = LogMessage::new();
        log_message.body_iid = Some(body_iid);

        let log_level = log_val[0].as_str().unwrap();
        log_message.prio = Some(util::get_log_level(log_level).into());
        track_event.log_message = Some(log_message).into();
    }

    if event_type != "COUNTER" {
        for (key, value) in event.into_iter() {
            if util::is_event_field(key) {
                continue;
            }
            if key == "flow_id" {
                let flow_id;
                if value.is_number() {
                    flow_id = value.as_u64().unwrap().to_string();
                } else {
                    flow_id = value.as_str().unwrap().to_string();
                }
                if !ids.flow_name_ids.contains_key(&flow_id) {
                    ids.flow_name_ids.insert(flow_id.clone(), gen_flow_id());
                }
                let flow_id = ids.flow_name_ids[&flow_id];
                track_event.flow_ids.push(flow_id);
                continue;
            }
            let mut debug_annotation = DebugAnnotation::new();
            let string_id_pair = get_string_id(key, ids);
            debug_annotation.name_field =
                Some(debug_annotation::Name_field::NameIid(string_id_pair.0));

            if string_id_pair.1 {
                let mut dan = DebugAnnotationName::new();
                dan.iid = Some(string_id_pair.0);
                dan.name = Some(key.to_string());
                interned_data.debug_annotation_names.push(dan);
            }

            if value.is_string() {
                let string_value_id_pair = get_string_id(value.as_str().unwrap(), ids);
                debug_annotation.value = Some(debug_annotation::Value::StringValueIid(
                    string_value_id_pair.0,
                ));

                if string_value_id_pair.1 {
                    let mut is = InternedString::new();
                    is.iid = Some(string_value_id_pair.0);
                    is.str = Some(value.as_str().unwrap().as_bytes().to_vec());
                    interned_data.debug_annotation_string_values.push(is);
                }
            } else if value.is_number() {
                debug_annotation.value =
                    Some(debug_annotation::Value::IntValue(value.as_i64().unwrap()));
            }

            track_event.debug_annotations.push(debug_annotation);
        }
    }

    packet.interned_data = Some(interned_data).into();
    packet.data = Some(trace_packet::Data::TrackEvent(track_event));
    trace.packet.push(packet);
}

//  Example call stack samples
// print(("call_stack", ("ts", nsecs), ("pid", pid), ("tid", tid), ("thread_name", comm), ("kstack", kstack), ("ustack", ustack)));
fn add_call_stack_sample(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    let mut event = HashMap::new();

    for i in 1..data.as_array().unwrap().len() {
        let pair = &data[i];
        assert!(
            pair.is_array() && pair.as_array().unwrap().len() == 2,
            "Expecting key/value tuples. Found {pair}"
        );
        let key = &pair[0];
        assert!(key.is_string(), "Expecting key to be a string. Found {key}");
        // do these have to be clones?
        event.insert(key.as_str().unwrap(), pair[1].clone());
    }

    util::validate_call_stack_sample(&event);

    let pid = event["pid"].as_u64().unwrap();
    let tid = event["tid"].as_u64().unwrap();
    if get_uuid_for_pid_tid(&pid, &tid, &ids).is_none() {
        // Track descriptor doesn't exist, let's make one
        add_track_descriptor_thread(trace, &pid, &tid, event["thread_name"].as_str(), ids);
    }

    let mut packet = TracePacket::new();
    packet.optional_trusted_packet_sequence_id =
        Some(trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(1));

    let mut perf_sample = PerfSample::new();
    perf_sample.cpu_mode = Some(profiling::CpuMode::MODE_USER.into());

    set_sequence_flags(&mut packet);

    let mut interned_data = InternedData::new();

    unsafe {
        if IS_FIRST_CALL_SAMPLE {
            let mut dummy_mapping = Mapping::new();
            dummy_mapping.iid = Some(1);
            interned_data.mappings.push(dummy_mapping);
            IS_FIRST_CALL_SAMPLE = false;
        }
    }

    perf_sample.pid = Some(event["pid"].as_u64().unwrap() as u32);
    perf_sample.tid = Some(event["tid"].as_u64().unwrap() as u32);

    if event.contains_key("cpu") {
        perf_sample.cpu = Some(event["cpu"].as_u64().unwrap() as u32);
    }

    let callstack_iid: Option<u64>;

    if event.contains_key("kstack") {
        if event.contains_key("ustack") {
            callstack_iid = process_call_stacks(
                &mut interned_data,
                ids,
                event["kstack"].as_str().unwrap(),
                event["ustack"].as_str(),
            );
        } else {
            callstack_iid = process_call_stacks(
                &mut interned_data,
                ids,
                event["kstack"].as_str().unwrap(),
                None,
            );
        }
    } else {
        callstack_iid = process_call_stacks(
            &mut interned_data,
            ids,
            event["ustack"].as_str().unwrap(),
            None,
        );
    }

    perf_sample.callstack_iid = callstack_iid;

    packet.timestamp = Some(event["ts"].as_u64().unwrap());
    packet.interned_data = Some(interned_data).into();
    packet.data = Some(trace_packet::Data::PerfSample(perf_sample));
    trace.packet.push(packet);
}

fn get_uuid_for_name(name: &str, ids: &Ids) -> Option<u64> {
    if ids.name_uuids.contains_key(name) {
        Some(ids.name_uuids[name])
    } else {
        None
    }
}

fn get_uuid_for_pid_tid(pid: &u64, tid: &u64, ids: &Ids) -> Option<u64> {
    if ids.pid_tid_uuids.contains_key(pid) {
        if ids.pid_tid_uuids[pid].contains_key(tid) {
            Some(ids.pid_tid_uuids[pid][tid])
        } else {
            None
        }
    } else {
        None
    }
}

fn add_track_descriptor_thread(
    trace: &mut Trace,
    pid: &u64,
    tid: &u64,
    thread_name: Option<&str>,
    ids: &mut Ids,
) -> u64 {
    let uuid: u64 = gen_uuid();
    let mut packet = TracePacket::new();

    if !ids.pid_tid_uuids.contains_key(pid) {
        ids.pid_tid_uuids.insert(pid.clone(), HashMap::new());
    }

    let pid_map = ids.pid_tid_uuids.get_mut(&pid);
    pid_map.unwrap().insert(tid.clone(), uuid.clone());

    let mut track_descriptor = TrackDescriptor::new();
    track_descriptor.uuid = Some(uuid.clone());

    let mut thread_descriptor = ThreadDescriptor::new();
    thread_descriptor.pid = Some(pid.clone() as i32);
    thread_descriptor.tid = Some(tid.clone() as i32);
    thread_descriptor.thread_name = if thread_name.is_none() {
        Some("unknown".to_string())
    } else {
        Some(thread_name.unwrap().to_string())
    };

    track_descriptor.thread = Some(thread_descriptor).into();
    packet.data = Some(trace_packet::Data::TrackDescriptor(track_descriptor));

    trace.packet.push(packet);

    uuid
}

fn gen_uuid() -> u64 {
    unsafe {
        TRACK_DESCRIPTOR_UUID += 1;
        TRACK_DESCRIPTOR_UUID
    }
}

fn gen_flow_id() -> u64 {
    unsafe {
        FLOW_UUID += 1;
        FLOW_UUID
    }
}

fn set_sequence_flags(packet: &mut TracePacket) {
    unsafe {
        if IS_FIRST_PACKET {
            packet.first_packet_on_sequence = Some(true);
            packet.previous_packet_dropped = Some(true);
            packet.sequence_flags = Some(
                (trace_packet::SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32)
                    | (trace_packet::SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32),
            );
            IS_FIRST_PACKET = false;
        } else {
            packet.sequence_flags =
                Some(trace_packet::SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32)
        }
    }
}

fn get_string_id(s: &str, ids: &mut Ids) -> (u64, bool) {
    let mut added = false;
    if !ids.string_ids.contains_key(s) {
        ids.interned_data_id += 1;
        ids.string_ids.insert(s.to_string(), ids.interned_data_id);
        added = true;
    }

    (ids.string_ids[s], added)
}

// If there is a second stack it's always the user stack
fn process_call_stacks(
    interned_data: &mut InternedData,
    ids: &mut Ids,
    stack1str: &str,
    stack2str: Option<&str>,
) -> Option<u64> {
    let stack1 = util::parse_stack_str(&stack1str);
    if stack2str.is_some() {
        let stack2 = util::parse_stack_str(stack2str.unwrap());
        let concat_stack = [stack1, stack2].concat();
        if concat_stack.len() == 0 {
            return None;
        }
        return Some(add_call_stack(&concat_stack, interned_data, ids));
    } else {
        if stack1.len() == 0 {
            return None;
        }
        return Some(add_call_stack(&stack1, interned_data, ids));
    }
}

fn add_call_stack(stack: &Vec<String>, interned_data: &mut InternedData, ids: &mut Ids) -> u64 {
    let mut stack_ids: Vec<u64> = Vec::new();
    for frame in stack {
        stack_ids.push(add_stack_frame(frame, interned_data, ids));
    }
    if !ids.call_stack_ids.contains_key(&stack_ids) {
        ids.interned_data_id += 1;
        let cs_id = ids.interned_data_id;
        ids.call_stack_ids.insert(stack_ids.clone(), cs_id);
        let mut callstack = Callstack::new();
        callstack.iid = Some(cs_id.clone());
        // Perfetto wants bottom frame first
        for x in stack_ids.into_iter().rev() {
            callstack.frame_ids.push(x);
        }
        interned_data.callstacks.push(callstack);
        return cs_id;
    }
    return ids.call_stack_ids[&stack_ids];
}

fn add_stack_frame(frame: &String, interned_data: &mut InternedData, ids: &mut Ids) -> u64 {
    let string_id_pair = get_string_id(frame, ids);

    if string_id_pair.1 {
        let mut is = InternedString::new();
        is.iid = Some(string_id_pair.0);
        is.str = Some(frame.as_bytes().to_vec());
        interned_data.function_names.push(is);

        let mut f = Frame::new();
        ids.interned_data_id += 1;
        f.iid = Some(ids.interned_data_id);
        f.function_name_id = Some(string_id_pair.0);
        f.mapping_id = Some(1);
        interned_data.frames.push(f);
        return ids.interned_data_id;
    }

    // The frame id is always one greater than the string id
    return string_id_pair.0 + 1;
}
