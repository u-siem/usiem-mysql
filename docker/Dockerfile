# Derived from official mysql image (our base image)
FROM mysql:8

COPY example.sql /docker-entrypoint-initdb.d/
COPY my.cnf /etc/mysql/my.cnf

ENV MYSQL_ROOT_PASSWORD my-secret-pw
RUN mkdir /var/log/mysql && chmod 777 /var/log/mysql

EXPOSE 3306 33060 33061
CMD ["mysqld"]