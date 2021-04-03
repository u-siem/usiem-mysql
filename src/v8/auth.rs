use std::borrow::Cow;
use usiem::events::auth::{AuthEvent, AuthLoginType, LocalLogin, LoginOutcome, RemoteLogin};
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::field_dictionary;
use usiem::events::{SiemEvent, SiemLog};

/// Parse log connection events
pub fn parse_connection(mut log: SiemLog, content: &str) -> Result<SiemLog, SiemLog> {
    let splited = content.split(" ").collect::<Vec<&str>>();
    if splited.len() < 4 {
        return Err(log);
    }
    if splited[1] != "on" && splited[3] != "using" {
        if splited[0] == "Access" && splited[1] == "denied" {
            return parse_login_failed(log, splited);
        }
        return Err(log);
    }
    if splited.len() != 5 {
        return Err(log);
    }
    let user_ip = splited[0];
    if splited[2] != "" {
        log.add_field("database.name", SiemField::Text(Cow::Owned(splited[2].to_string())));
    }
    let protocol = splited[4].to_string();
    let (user, source_address) = match parse_user(user_ip) {
        Ok((user, source_address)) => match SiemIp::from_ip_str(source_address) {
            Ok(source_ip) => {
                log.add_field(field_dictionary::SOURCE_IP, SiemField::IP(source_ip));
                (user.to_string(),source_address.to_string())

            }
            Err(_) => (user.to_string(), source_address.to_string()),
        },
        Err(_) => return Err(log),
    };
    let hostname = match log.field("host.hostname") {
        Some(field) => match field {
            SiemField::Text(field) => Cow::Owned(field.to_string()),
            _ => Cow::Borrowed("MySQL"),
        },
        None => Cow::Borrowed("MySQL"),
    };

    log.add_field("user.name", SiemField::User(user.to_string()));
    log.add_field("network.protocol", SiemField::Text(Cow::Owned(protocol)));
    let event = if source_address == "localhost" || source_address == "127.0.0.1" {
        AuthEvent {
            hostname: hostname,
            outcome: LoginOutcome::ESTABLISH,
            login_type: AuthLoginType::Local(LocalLogin {
                user_name: Cow::Owned(user),
                domain: Cow::Borrowed("mysql"),
            }),
        }
    }else{
        AuthEvent {
            hostname: hostname,
            outcome: LoginOutcome::ESTABLISH,
            login_type: AuthLoginType::Remote(RemoteLogin {
                user_name: Cow::Owned(user),
                domain: Cow::Borrowed("mysql"),
                source_address : Cow::Owned(source_address)
            }),
        }
    };
    
    log.set_event(SiemEvent::Auth(event));
    Ok(log)
    //root@172.17.0.1 on web_test using TCP/IP
}

fn parse_user<'a>(content: &'a str) -> Result<(&'a str, &'a str), ()> {
    let splited = content.split("@").collect::<Vec<&str>>();
    
    if splited.len() != 2 {
        return Err(());
    } else {
        let mut user = splited[0];
        let mut address = splited[1];
        if user.len() > 2 && &user[0..1] == "'" && &user[user.len() -1 ..] == "'" {
            user = &user[1..user.len()-1];
        }
        if address.len() > 2 && &address[0..1] == "'" && &address[address.len() -1 ..] == "'" {
            address = &address[1..address.len()-1];
        }
        return Ok((user, address));
    }
}

fn parse_login_failed(mut log: SiemLog, content: Vec<&str>) -> Result<SiemLog, SiemLog> {
    if content.len() < 5 {
        return Err(log);
    }
    let (user, source_address) = match parse_user(content[4]) {
        Ok((user, source_address)) => match SiemIp::from_ip_str(source_address) {
            Ok(source_ip) => {
                log.add_field(field_dictionary::SOURCE_IP, SiemField::IP(source_ip));
                (user.to_string(),source_address.to_string())

            }
            Err(_) => (user.to_string(), source_address.to_string()),
        },
        Err(_) => return Err(log),
    };
    let hostname = match log.field("host.hostname") {
        Some(field) => match field {
            SiemField::Text(field) => Cow::Owned(field.to_string()),
            _ => Cow::Borrowed("MySQL"),
        },
        None => Cow::Borrowed("MySQL"),
    };

    let event = if source_address == "localhost" || source_address == "127.0.0.1" {
        AuthEvent {
            hostname: hostname,
            outcome: LoginOutcome::FAIL,
            login_type: AuthLoginType::Local(LocalLogin {
                user_name: Cow::Owned(user),
                domain: Cow::Borrowed("mysql"),
            }),
        }
    }else{
        AuthEvent {
            hostname: hostname,
            outcome: LoginOutcome::FAIL,
            login_type: AuthLoginType::Remote(RemoteLogin {
                user_name: Cow::Owned(user),
                domain: Cow::Borrowed("mysql"),
                source_address : Cow::Owned(source_address)
            }),
        }
    };
    log.set_event(SiemEvent::Auth(event));
    return Ok(log)
}
/*
2021-04-03T10:55:34.990497Z         9 Connect   root@localhost on  using Socket
2021-04-03T10:55:34.994886Z         9 Connect   Access denied for user 'root'@'localhost' (using password: YES)
2021-04-03T10:56:15.157431Z        10 Connect   root@172.17.0.1 on web_test using TCP/IP
2021-04-03T10:56:15.158251Z        10 Connect   Access denied for user 'root'@'172.17.0.1' (using password: YES)
*/