use crate::protos;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use protos::protos_gen::perfetto_bpftrace::{log_message, track_event};

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
    field == "type"
        || field == "ts"
        || field == "name"
        || field == "thread_name"
        || field == "pid"
        || field == "tid"
        || field == "log"
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
