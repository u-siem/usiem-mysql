CREATE DATABASE web_test;
USE web_test;
CREATE TABLE `users` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `email` varchar(255) COLLATE utf8_bin NOT NULL,
    `password` varchar(255) COLLATE utf8_bin NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
AUTO_INCREMENT=1 ;
INSTALL COMPONENT 'file://component_log_sink_json';
SET PERSIST log_error_services = 'log_sink_json; log_filter_internal; log_sink_json';