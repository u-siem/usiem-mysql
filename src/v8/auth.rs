use usiem::events::field::{SiemField, SiemIp};
use usiem::events::{SiemLog, SiemEvent};
use usiem::events::auth::{AuthEvent, AuthLoginType, LoginOutcome, RemoteLogin, LocalLogin};
use std::borrow::Cow;

/// Parse log connection events
pub fn parse_connection(mut log : SiemLog, content : &str) -> Result<SiemLog, SiemLog> {
    let splited = content.split(" ").collect::<Vec<&str>>();
    if splited.len() != 5 {
        return Err(log)
    }
    if splited[1] != "on" && splited[3] != "using" {
        return Err(log)
    }
    let user_ip = splited[0];
    let database = splited[2].to_string();
    let protocol = splited[4].to_string();
    let (user,source_ip) = match parse_user(user_ip) {
        Ok((user,source_ip)) => {
            match SiemIp::from_ip_str(source_ip) {
                Ok(source_ip) => (user.to_string(),Some(source_ip)),
                Err(_) =>(user.to_string(),None),
            }
        },
        Err(_) => return Err(log)
    };
    let hostname = match log.field("host.hostname") {
        Some(field) => {
            match field {
                SiemField::Text(field) => {
                    Cow::Owned(field.to_string())
                },
                _=> Cow::Borrowed("MySQL")
            }
        },
        None => Cow::Borrowed("MySQL")
    };

    
    log.add_field("user.name", SiemField::User(user.to_string()));
    log.add_field("network.protocol", SiemField::Text(Cow::Owned(protocol)));
    log.add_field("database.name", SiemField::Text(Cow::Owned(database)));
    match source_ip {
        Some(source_ip) => {
            let event = AuthEvent {
                hostname : hostname,
                outcome : LoginOutcome::SUCESS,
                login_type : AuthLoginType::Remote(RemoteLogin {
                    user_name : Cow::Owned(user),
                    domain : Cow::Borrowed("mysql"),
                    source_ip : source_ip
                })
            };
            log.set_event(SiemEvent::Auth(event));
        },
        None => {
            let event = AuthEvent {
                hostname : hostname,
                outcome : LoginOutcome::SUCESS,
                login_type : AuthLoginType::Local(LocalLogin {
                    user_name : Cow::Owned(user),
                    domain : Cow::Borrowed("mysql")
                })
            };
            log.set_event(SiemEvent::Auth(event));
        }
    }
    Ok(log)
    //root@172.17.0.1 on web_test using TCP/IP
}


fn parse_user<'a>(content :&'a str) -> Result<(&'a str,&'a str),()> {
    let splited = content.split("@").collect::<Vec<&str>>();
    if splited.len() != 2 {
        return Err(())
    }else{
        return Ok((splited[0],splited[1]))
    }
} 