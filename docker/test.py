import pymysql.cursors



for i in range(0,10000):
    # Connect to the database
    connection = pymysql.connect(host='localhost',
                             user='root',
                             password='my-secret-pw',
                             database='web_test',
                             cursorclass=pymysql.cursors.DictCursor)