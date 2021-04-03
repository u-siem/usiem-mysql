use chrono::prelude::{DateTime};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::SiemField;
use usiem::events::SiemLog;
mod auth;
use auth::{parse_connection};

pub fn valid_general_log(log : &SiemLog) -> bool {
    let log_line = log.message();
    let fisr_char = match log_line.chars().next() {
        Some(chr) => chr,
        None => return false
    };
    !(fisr_char > '9' || fisr_char < '0')
}

pub fn parse_general_log(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let fisr_char = match log_line.chars().next() {
        Some(chr) => chr,
        None => return Err(LogParsingError::NoValidParser(log))
    };
    if fisr_char > '9' || fisr_char < '0' {
        return Err(LogParsingError::NoValidParser(log));
    }
    let fields = extract_general_fields(log_line);
    println!("{}",fields.len());
    if fields.len() != 4 {
        return Err(LogParsingError::NoValidParser(log))
    }
    let event_created = match DateTime::parse_from_rfc3339(fields[0]) {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => return Err(LogParsingError::NoValidParser(log)),
    };
    let event_dataset = fields[2].to_string();
    let session_id = fields[1].to_string();
    let content = fields[3].to_string();
    match &event_dataset[..] {
        "Quit" => {},
        "Query" => {
            log.add_field("database.query", SiemField::Text(Cow::Owned(content)));
        },
        "Connect" => {
            log = match parse_connection(log, &content[..]) {
                Err(log) => log,
                Ok(log) => log,
            };
        },
        _ => {}
    }
    log.set_event_created(event_created);
    match session_id.parse::<u32>() {
        Ok(session_id) => {
            log.add_field("session.id", SiemField::U32(session_id));
        },
        Err(_) => {
            log.add_field("session.name", SiemField::Text(Cow::Owned(session_id)));
        }
    };
    
    log.add_field("event.dataset", SiemField::Text(Cow::Owned(event_dataset)));
    log.set_service(Cow::Borrowed("MySQL"));
    log.set_product(Cow::Borrowed("MySQL"));
    log.set_category(Cow::Borrowed("Database"));
    return Ok(log)
    
}

pub fn extract_general_fields<'a>(message: &'a str) -> Vec<&'a str> {
    let mut field_map = Vec::with_capacity(4);
    let mut start_field = 0;
    let mut last_char = ' ';
    for (i, c) in message.char_indices() {
        if c == ' ' {
            if last_char != ' ' {
                field_map.push(&message[start_field..i]);
                if field_map.len() == 3 {
                    field_map.push(&message[i..].trim());
                    break;
                }                
            }
            start_field = i + 1;
        }
        last_char = c;
    }
    if field_map.len() == 2 {
        field_map.push(&message[start_field..].trim());
        field_map.push(&message[start_field..].trim());
    }
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{parse_general_log, extract_general_fields};
    use usiem::events::{SiemLog, SiemEvent};
    use usiem::events::field::{SiemIp, SiemField};
    use usiem::events::auth::{AuthLoginType,LoginOutcome};

    #[test]
    fn test_extract_fields() {
        let log = "2021-04-02T18:39:02.974916Z        22 Query     SELECT `id`, `password` FROM `users` WHERE `email`='webmaster@python.org' OR 1=1 -- '\n AND `password`='0'";
        let map = extract_general_fields(log);
        assert_eq!(map.get(0), Some(&"2021-04-02T18:39:02.974916Z"));
        assert_eq!(map.get(1), Some(&"22"));
        assert_eq!(map.get(2), Some(&"Query"));
        assert_eq!(map.get(3), Some(&"SELECT `id`, `password` FROM `users` WHERE `email`='webmaster@python.org' OR 1=1 -- '\n AND `password`='0'"));
    }
    #[test]
    fn test_extract_fields_empty() {
        let log = "2021-04-02T18:30:15.862098Z        17 Quit";
        let map = extract_general_fields(log);
        assert_eq!(map.get(0), Some(&"2021-04-02T18:30:15.862098Z"));
        assert_eq!(map.get(1), Some(&"17"));
        assert_eq!(map.get(2), Some(&"Quit"));
        assert_eq!(map.get(3), Some(&"Quit"));// Special case
    }

    #[test]
    fn test_parse_log() {
        let log = "2021-04-02T18:08:21.261667Z        11 Connect   root@172.17.0.1 on web_test using TCP/IP";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Connect")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(11)));
                assert_eq!(log.field("user.name"), Some(&SiemField::User(String::from("root"))));
                assert_eq!(log.field("source.ip"), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").unwrap())));
                assert_eq!(log.field("database.name"), Some(&SiemField::from_str("web_test")));
                assert_eq!(log.field("network.protocol"), Some(&SiemField::from_str("TCP/IP")));
                assert_eq!(log.field("event.outcome"), Some(&SiemField::from_str(LoginOutcome::ESTABLISH.to_string())));
                match log.event() {
                    SiemEvent::Auth(ath) => {
                        match ath.login_type() {
                            AuthLoginType::Remote(_rmt) => {
                            },
                            _ => {panic!("Invalid Log event")}
                        }
                    },
                    _ => {panic!("Invalid Log event")}
                }
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }

    #[test]
    fn test_parse_log_query() {
        let log = "2021-04-02T18:39:02.974916Z        22 Query     SELECT `id`, `password` FROM `users` WHERE `email`='webmaster@python.org' OR 1=1 -- '\n AND `password`='0'";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Query")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(22)));
                assert_eq!(log.field("database.query"), Some(&SiemField::from_str("SELECT `id`, `password` FROM `users` WHERE `email`='webmaster@python.org' OR 1=1 -- '\n AND `password`='0'")));
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }

    #[test]
    fn test_parse_log_quit() {
        let log = "2021-04-02T18:39:02.975700Z        22 Quit";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Quit")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(22)));
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }
    #[test]
    fn test_parse_log_empty_db() {
        let log = "2021-04-03T10:55:34.990497Z         9 Connect   root@localhost on  using Socket";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Connect")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(9)));
                assert_eq!(log.field("user.name"), Some(&SiemField::User(String::from("root"))));
                assert_eq!(log.field("database.name"), None);
                assert_eq!(log.field("network.protocol"), Some(&SiemField::from_str("Socket")));
                assert_eq!(log.field("event.outcome"), Some(&SiemField::from_str(LoginOutcome::ESTABLISH.to_string())));
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }
    #[test]
    fn test_parse_log_access_denied() {
        let log = "2021-04-03T10:55:34.994886Z         9 Connect   Access denied for user 'root'@'localhost' (using password: YES)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Connect")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(9)));
                assert_eq!(log.field("user.name"), Some(&SiemField::User(String::from("root"))));
                assert_eq!(log.field("event.outcome"), Some(&SiemField::from_str(LoginOutcome::FAIL.to_string())));
                match log.event() {
                    SiemEvent::Auth(ath) => {
                        match ath.login_type() {
                            AuthLoginType::Local(_locl) => {
                            },
                            _ => {panic!("Invalid Log event")}
                        }
                    },
                    _ => {panic!("Invalid Log event")}
                }
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }
    #[test]
    fn test_parse_log_remote_access_denied() {
        let log = "2021-04-03T10:56:15.158251Z        10 Connect   Access denied for user 'root'@'172.17.0.1' (using password: YES)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log_parsed = parse_general_log(log);
        match log_parsed {
            Ok(log) => {
                assert_eq!(log.service(), "MySQL");
                assert_eq!(log.field("event.dataset"), Some(&SiemField::from_str("Connect")));
                assert_eq!(log.field("session.id"), Some(&SiemField::U32(10)));
                assert_eq!(log.field("user.name"), Some(&SiemField::User(String::from("root"))));
                assert_eq!(log.field("source.ip"), Some(&SiemField::IP(SiemIp::from_ip_str("172.17.0.1").unwrap())));
                assert_eq!(log.field("event.outcome"), Some(&SiemField::from_str(LoginOutcome::FAIL.to_string())));
                match log.event() {
                    SiemEvent::Auth(ath) => {
                        match ath.login_type() {
                            AuthLoginType::Remote(_rmt) => {
                            },
                            _ => {panic!("Invalid Log event")}
                        }
                    },
                    _ => {panic!("Invalid Log event")}
                }
            },
            Err(_) => {panic!("Cannot parse log")}
        }
    }
}
