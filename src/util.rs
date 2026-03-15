use crate::protos;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use protos::protos_gen::perfetto_bpftrace::{log_message, track_event};
use serde_json::Value;

pub fn get_log_level(log_level: &str) -> log_message::Priority {
    match log_level {
        "UNSPECIFIED" => {
            return log_message::Priority::PRIO_UNSPECIFIED;
        }
        "UNUSED" => {
            return log_message::Priority::PRIO_UNUSED;
        }
        "VERBOSE" => {
            return log_message::Priority::PRIO_VERBOSE;
        }
        "DEBUG" => {
            return log_message::Priority::PRIO_DEBUG;
        }
        "INFO" => {
            return log_message::Priority::PRIO_INFO;
        }
        "WARN" => {
            return log_message::Priority::PRIO_WARN;
        }
        "ERROR" => {
            return log_message::Priority::PRIO_ERROR;
        }
        "FATAL" => {
            return log_message::Priority::PRIO_FATAL;
        }
        _ => panic!("Error: Unknown log level {log_level}"),
    }
}

pub fn is_event_field(field: &str) -> bool {
    field == "type" || field == "ts" || field == "name" || field == "log" || field == "track" || field == "track_parent"
}

fn is_valid_event_type(event: &str) -> bool {
    event == "BEGIN" || event == "COUNTER" || event == "END" || event == "INSTANT"
}

pub fn parse_stack_str(stack1str: &str) -> Vec<String> {
    let mut stack1: Vec<&str> = stack1str.split('\n').collect();
    stack1.remove(0);
    stack1.pop();
    return stack1.into_iter().map(|x| x.trim().to_string()).collect();
}

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn get_track_event_type(event_type: &str) -> track_event::Type {
    match event_type {
        "BEGIN" => {
            return track_event::Type::TYPE_SLICE_BEGIN;
        }
        "END" => {
            return track_event::Type::TYPE_SLICE_END;
        }
        "INSTANT" => {
            return track_event::Type::TYPE_INSTANT;
        }
        "COUNTER" => {
            return track_event::Type::TYPE_COUNTER;
        }
        _ => panic!("Error: Unknown event type {event_type}"),
    }
}

pub fn validate_track_event(event: &HashMap<&str, serde_json::Value>) {
    assert!(
        event.contains_key("name"),
        "Error: track event must have a name"
    );
    assert!(
        event.contains_key("ts"),
        "Error: track event must have a ts (timestamp)"
    );
    let event_type = event["type"].as_str().unwrap();
    assert!(
        event.contains_key("type"),
        "Error: track must have a valid type"
    );
    assert!(
        is_valid_event_type(event_type),
        "Error: track must have a valid type. Found {event_type}"
    );
}

pub fn json_line_to_folded_stacks(line: &str) -> Option<String> {
    let json_line: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return None,
    };

    if json_line["type"] != "value" {
        return None;
    }

    let data = match json_line["data"].as_array() {
        Some(arr) if !arr.is_empty() => arr,
        _ => return None,
    };

    if data[0] != "call_stack" {
        return None;
    }

    let mut event = HashMap::new();
    for pair in &data[1..] {
        if let Some(pair_arr) = pair.as_array() {
            if pair_arr.len() == 2 {
                if let Some(key) = pair_arr[0].as_str() {
                    event.insert(key, &pair_arr[1]);
                }
            }
        }
    }

    // Build frames: ustack (root) first, then kstack (towards leaf)
    let mut frames: Vec<String> = Vec::new();

    if let Some(ustack) = event.get("ustack").and_then(|v| v.as_str()) {
        let mut uframes = parse_stack_str(ustack);
        // parse_stack_str returns top-to-bottom; reverse for folded format (bottom-to-top)
        uframes.reverse();
        frames.extend(uframes);
    }

    if let Some(kstack) = event.get("kstack").and_then(|v| v.as_str()) {
        let mut kframes = parse_stack_str(kstack);
        kframes.reverse();
        frames.extend(kframes);
    }

    if frames.is_empty() {
        return None;
    }

    // Folded stacks format: "frame1;frame2;frame3 count"
    Some(format!("{} 1", frames.join(";")))
}

pub fn validate_call_stack_sample(event: &HashMap<&str, serde_json::Value>) {
    assert!(
        event.contains_key("ts"),
        "Error: call stack sample must have a ts (timestamp)"
    );
    assert!(
        event.contains_key("pid"),
        "Error: call stack sample must have a pid"
    );
    assert!(
        event.contains_key("tid"),
        "Error: call stack sample must have a tid"
    );
    assert!(
        event.contains_key("ustack") || event.contains_key("kstack"),
        "Error: call stack sample must have a ustack or a kstack or both"
    );
}
