use usiem::events::field::{SiemField, SiemIp};
use usiem::events::SiemLog;
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
    log.add_field("user.name", SiemField::User(user));
    log.add_field("network.protocol", SiemField::Text(Cow::Owned(protocol)));
    log.add_field("database.name", SiemField::Text(Cow::Owned(database)));
    match source_ip {
        Some(source_ip) => {
            log.add_field("source.ip", SiemField::IP(source_ip));
        },
        None => {}
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