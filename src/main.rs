use std::collections::HashMap;
// use std::collections::HashSet;
use std::fs;
use std::io;

use serde_json::Value;

mod protos;

use protobuf::Message;
use protos::protos_gen::perfetto_bpftrace::{
    DebugAnnotation, DebugAnnotationName, CounterDescriptor, EventName, InternedData, InternedString, Trace, TracePacket, TrackDescriptor, ThreadDescriptor, TrackEvent, counter_descriptor, debug_annotation, track_descriptor, track_event, trace_packet};

// cargo build && sudo bpftrace ~/jordan.bt -f json | ./target/debug/btetto

struct Ids {
    flow_name_ids: HashMap<String, u64>,
    name_uuids: HashMap<String, u64>,
    pid_tid_uuids: HashMap<u64, HashMap<u64, u64>>,
    string_ids: HashMap<String, u64>,
    interned_data_id: u64,
}

static mut IS_FIRST_PACKET: bool = true;
static mut IS_TRACE_DONE: bool = false;
static mut TRACK_DESCRIPTOR_UUID: u64 = 1;
static mut FLOW_UUID: u64 = 1;

fn main() {
    let mut trace = Trace::new();
    let mut ids = Ids { flow_name_ids: HashMap::new(), name_uuids: HashMap::new(), pid_tid_uuids: HashMap::new(), string_ids: HashMap::new(), interned_data_id: 1 };
    
    let packet = TracePacket::new();
    trace.packet.push(packet);
    
    ctrlc::set_handler(|| {
        unsafe {
            IS_TRACE_DONE = true;   
        }
    })
    .expect("Error setting Ctrl-C handler");
    
    let mut input = String::new();
    loop {
        unsafe {
            if IS_TRACE_DONE {
                break;
            }   
        }
        
        io::stdin().read_line(&mut input).expect("Failed to read line");
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
    
    println!("Num trace events {}", trace.packet.len());
    
    let out_bytes: Vec<u8> = trace.write_to_bytes().unwrap();
    
    fs::write("bpftrace_trace.binpb", out_bytes).expect("Could not write Perfetto protobuf file");
}

fn parse_raw_data(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    assert!(data.is_array(), "Expecting data to be a array.");
    
    if data.as_array().unwrap().len() == 0 {
        return
    }
    
    let data_type = &data[0];
    
    if data_type == "track_descriptor" {
        add_track_descriptor(trace, &data, ids);
    } else if data_type == "track_event" {
        add_track_event(trace, &data, ids);
    } else if data_type == "call_stack" {
        // add_call_stack_sample(trace, data, data_len);
        return;
    } else {
        panic!("The first field is not a valid trace data type");
    }
}

// Valid track descriptor tuples
// print(("track_descriptor", ("thread_name", comm), ("pid", pid), ("tid", tid)));
// print(("track_descriptor", ("name", "my custom track"), ("parent", "Top Parent")));
// print(("track_descriptor", ("counter", "counter name"), ("unit", "count")));
fn add_track_descriptor(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    let mut descriptor = HashMap::new();
    
    for i in 1..data.as_array().unwrap().len() {
        let pair = &data[i];
        assert!(pair.is_array() && pair.as_array().unwrap().len() == 2, "Expecting key/value tuples. Found {pair}");
        let key = &pair[0];
        assert!(key.is_string(), "Expecting key to be a string. Found {key}");
        // do these have to be clones?
        descriptor.insert(key.as_str().unwrap(), pair[1].clone());
    }
    
    if descriptor.contains_key("name") {
        add_track_descriptor_name(descriptor, trace, ids);
    } else if descriptor.contains_key("thread_name") {
        add_track_descriptor_thread(descriptor, trace, ids);
    } else if descriptor.contains_key("counter") {
        add_track_descriptor_counter(descriptor, trace, ids);
    } else {
        panic!("Error: Track descriptor is invalid");
    }
}

fn add_track_descriptor_name(descriptor: HashMap<&str, Value>, trace: &mut Trace, ids: &mut Ids)
{
    let track_name = descriptor["name"].as_str().unwrap();
    let track_uuid = get_uuid_for_name(&track_name, &ids);
    if track_uuid.is_some() {
        // Already have this track descriptor, no need to re-add it
        return;
    }
    
    let uuid = gen_uuid();
    ids.name_uuids.insert(track_name.to_string(), uuid.clone());
    
    let mut packet = TracePacket::new();    
    let mut track_descriptor = TrackDescriptor::new();
    track_descriptor.static_or_dynamic_name = Some(track_descriptor::Static_or_dynamic_name::Name(track_name.to_string()));
    track_descriptor.uuid = Some(uuid);
    
    if descriptor.contains_key("parent") {
        let parent_uuid = get_uuid_for_name(&descriptor["parent"].as_str().unwrap(), &ids);
        if parent_uuid.is_none() {
            let parent_name = descriptor["name"].clone();
            panic!("Error: can't find track descriptor with name {}", parent_name);
        }
        track_descriptor.parent_uuid = parent_uuid;
    }
    
    packet.data = Some(trace_packet::Data::TrackDescriptor(track_descriptor));
    trace.packet.push(packet);
}

fn add_track_descriptor_thread(descriptor: HashMap<&str, Value>, trace: &mut Trace, ids: &mut Ids)
{
    if !descriptor.contains_key("pid") || !descriptor.contains_key("tid") {
        panic!("Error: track descriptor thread_name needs to have a pid and a tid");
    }
    
    let pid = descriptor["pid"].as_u64().unwrap();
    let tid = descriptor["tid"].as_u64().unwrap();
    
    add_track_descriptor_thread_impl(trace, &pid, &tid, descriptor["thread_name"].as_str(), ids);
}

fn add_track_descriptor_counter(descriptor: HashMap<&str, Value>, trace: &mut Trace, ids: &mut Ids)
{
    let counter_name = descriptor["counter"].as_str().unwrap();
    let track_uuid = get_uuid_for_name(&counter_name, &ids);
    if track_uuid.is_some() {
        // Already have this track descriptor, no need to re-add it
        return;
    }
    
    let uuid = gen_uuid();
    ids.name_uuids.insert(counter_name.to_string(), uuid.clone());
    
    let mut packet = TracePacket::new();    
    let mut track_descriptor = TrackDescriptor::new();
    track_descriptor.static_or_dynamic_name = Some(track_descriptor::Static_or_dynamic_name::Name(counter_name.to_string()));
    track_descriptor.uuid = Some(uuid);
    
    if !descriptor.contains_key("unit") {
        panic!("Error: track descriptor counter needs to have a 'unit' tuple");
    }
    
    let unit = descriptor["unit"].as_str().unwrap();
    
    let mut counter_descriptor = CounterDescriptor::new();
    
    match unit {
        "unspecified" => {
            counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_UNSPECIFIED.into())
        },
        "count" => {
            counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_COUNT.into())
        },
        "sized_bytes" => {
            counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_SIZE_BYTES.into())
        },
        "time_ns" => {
            counter_descriptor.unit = Some(counter_descriptor::Unit::UNIT_TIME_NS.into())
        },
        _=> panic!("Error: Unknown unit type {}", unit)
    }
    
    track_descriptor.counter = Some(counter_descriptor).into();
    packet.data = Some(trace_packet::Data::TrackDescriptor(track_descriptor));
    trace.packet.push(packet);
    
}

// Example track events
// print(("track_event", ("name", "page_fault_user"), ("type", "BEGIN"), ("ts", $start), ("track_name", "Sub Parent A")));
// print(("track_event", ("name", "page_fault_user"), ("type", "END"), ("ts", nsecs), ("track_name", "Sub Parent A")));
// print(("track_event", ("name", "page_fault_user"), ("type", "BEGIN"), ("ts", $start), ("pid", pid), ("tid", tid), ("thread_name", comm), ("__a_bananas", 10), ("__a_greeting", "hello")));
fn add_track_event(trace: &mut Trace, data: &Value, ids: &mut Ids) {
    let mut event = HashMap::new();
    
    for i in 1..data.as_array().unwrap().len() {
        let pair = &data[i];
        assert!(pair.is_array() && pair.as_array().unwrap().len() == 2, "Expecting key/value tuples. Found {pair}");
        let key = &pair[0];
        assert!(key.is_string(), "Expecting key to be a string. Found {key}");
        // do these have to be clones?
        event.insert(key.as_str().unwrap(), pair[1].clone());
    }
    
    validate_track_event(&event);
    
    let mut track_uuid: Option<u64>;
    
    if event.contains_key("track_name") {
        let track_name = event["track_name"].as_str().unwrap();
        track_uuid = get_uuid_for_name(track_name, &ids);
        if track_uuid.is_none() {
            println!("Error: track name {} not found in track descriptors. You must emit a track descriptor tuple for each track_name track_event. Skipping", track_name); 
            return
        }
    } else if event.contains_key("pid") && event.contains_key("tid") {
        let pid = event["pid"].as_u64().unwrap();
        let tid = event["tid"].as_u64().unwrap();
        track_uuid = get_uuid_for_pid_tid(&pid, &tid, &ids);
        if track_uuid.is_none() {
            // Track descriptor doesn't exist, let's make one
            track_uuid = Some(add_track_descriptor_thread_impl(trace, &pid, &tid, event["thread_name"].as_str(), ids))
        }
    } else {
        panic!("Error: track event must have either a pid and tid or a track_name");
    }
    
    let mut packet = TracePacket::new();
    packet.optional_trusted_packet_sequence_id = Some(trace_packet::Optional_trusted_packet_sequence_id::TrustedPacketSequenceId(1));
    
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
    
    let event_type = event["type"].as_str().unwrap();
    
    match event_type {
        "BEGIN" => {
            track_event.type_ = Some(track_event::Type::TYPE_SLICE_BEGIN.into());
        },
        "END" => {
            track_event.type_ = Some(track_event::Type::TYPE_SLICE_END.into());
        },
        "INSTANT" => {
            track_event.type_ = Some(track_event::Type::TYPE_INSTANT.into());
        },
        "COUNTER" => {
            track_event.type_ = Some(track_event::Type::TYPE_COUNTER.into());
            track_event.counter_value_field = Some(track_event::Counter_value_field::CounterValue(event["counter_value"].as_i64().unwrap()));
        }
        _=> panic!("Error: Unknown event type {event_type}")
    }
    
    if event_type != "COUNTER" {
        for (key, value) in event.into_iter() {
            if is_event_field(key) {
                continue;
            }
            if key == "flow_name" {
                let flow_name = value.as_str().unwrap();
                if !ids.flow_name_ids.contains_key(flow_name) {
                    ids.flow_name_ids.insert(flow_name.to_string(), gen_flow_id());
                }
                let flow_id = ids.flow_name_ids[flow_name];
                track_event.flow_ids.push(flow_id);
                continue;
            }
            let mut debug_annotation = DebugAnnotation::new();
            let string_id_pair = get_string_id(key, ids);
            debug_annotation.name_field = Some(debug_annotation::Name_field::NameIid(string_id_pair.0));
            
            if string_id_pair.1 {
                let mut dan = DebugAnnotationName::new();
                dan.iid = Some(string_id_pair.0);
                dan.name = Some(key.to_string());
                interned_data.debug_annotation_names.push(dan);
            }
            
            if value.is_string() {
                let string_value_id_pair = get_string_id(value.as_str().unwrap(), ids);
                debug_annotation.value = Some(debug_annotation::Value::StringValueIid(string_value_id_pair.0));
                
                if string_value_id_pair.1 {
                    let mut is = InternedString::new();
                    is.iid = Some(string_value_id_pair.0);
                    is.str = Some(value.as_str().unwrap().as_bytes().to_vec());
                    interned_data.debug_annotation_string_values.push(is);
                }
            } else if value.is_number() {
                debug_annotation.value = Some(debug_annotation::Value::IntValue(value.as_i64().unwrap()));
            }
            
            track_event.debug_annotations.push(debug_annotation);
        }
    }
    
    packet.interned_data = Some(interned_data).into();
    packet.data = Some(trace_packet::Data::TrackEvent(track_event));
    trace.packet.push(packet);
    
}

fn validate_track_event(event: &HashMap<&str, serde_json::Value>) {
    assert!(event.contains_key("name"), "Error: track event must have a name");
    assert!(event.contains_key("ts"), "Error: track event must have a ts (timestamp)");
    let event_type = event["type"].as_str().unwrap();
    assert!(event.contains_key("type"), "Error: track must have a valid type");
    assert!(is_valid_event_type(event_type), "Error: track must have a valid type. Found {event_type}");
}

fn is_event_field(field: &str) -> bool {
    field == "type" || field == "ts" || field == "name" || field == "thread_name" || field == "pid" || field == "tid"
}

fn is_valid_event_type(event: &str) -> bool {
    event == "BEGIN" || event == "COUNTER" || event == "END" || event == "INSTANT"
}

fn get_uuid_for_name(name: &str, ids: &Ids) ->  Option<u64> {
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

fn add_track_descriptor_thread_impl(trace: &mut Trace, pid: &u64, tid: &u64, thread_name: Option<&str>, ids: &mut Ids) -> u64 {
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
    thread_descriptor.thread_name = if thread_name.is_none() { Some("unknown".to_string()) } else { Some(thread_name.unwrap().to_string()) };
    
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
            packet.sequence_flags = Some((trace_packet::SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32) | (trace_packet::SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32));
            IS_FIRST_PACKET = false;
        } else {
            packet.sequence_flags = Some(trace_packet::SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32)
        }
    }
}

fn get_string_id(s: &str, ids: &mut Ids) -> (u64, bool)
{
    let mut added = false;
    if !ids.string_ids.contains_key(s) {
        ids.interned_data_id += 1;
        ids.string_ids.insert(s.to_string(), ids.interned_data_id);
        added = true;
    }
    
    (ids.string_ids[s], added)
}