docker run --name usiem-mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql:8
docker exec -it usiem-mysql mysql -p