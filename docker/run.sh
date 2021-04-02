docker stop usiem-mysql-test
docker rm usiem-mysql-test
docker build -t usiem-mysql .
docker run -dit --name usiem-mysql-test -p 3306:3306 -e MYSQL_ROOT_PASSWORD=my-secret-pw -d usiem-mysql
docker exec -it $(docker ps -q) /bin/bash

docker exec -it usiem-mysql mysql -p