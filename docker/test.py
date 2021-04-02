import pymysql.cursors

# Connect to the database
connection = pymysql.connect(host='localhost',
                             user='root',
                             password='my-secret-pw',
                             database='web_test',
                             cursorclass=pymysql.cursors.DictCursor)

with connection:
    with connection.cursor() as cursor:
        # Create a new record
        sql = "INSERT INTO `users` (`email`, `password`) VALUES (%s, %s)"
        cursor.execute(sql, ('webmaster@python.org', 'very-secret'))

    # connection is not autocommit by default. So you must commit to save
    # your changes.
    connection.commit()

    with connection.cursor() as cursor:
        # Read a single record
        sql = "SELECT `id`, `password` FROM `users` WHERE `email`=%s"
        cursor.execute(sql, ('webmaster@python.org',))
        result = cursor.fetchone()
        print(result)
    
    # SQLinjection

    with connection.cursor() as cursor:
        # Read a single record
        argument = "webmaster@python.org"
        password = "0' OR 1=1 # "
        sql = "SELECT `id`, `password` FROM `users` WHERE `email`=%s AND `password`='" + password +"'"
        cursor.execute(sql,(argument,))
        result = cursor.fetchone()
        print(result)
    
    with connection.cursor() as cursor:
        # Read a single record
        argument = "webmaster@python.org' OR 1=1 #"
        password = "0"
        sql = "SELECT `id`, `password` FROM `users` WHERE `email`='" + argument + "'\n AND `password`='" + password +"'"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

    with connection.cursor() as cursor:
        # Read a single record
        argument = "webmaster@python.org' OR 1=1 -- "
        password = "0"
        sql = "SELECT `id`, `password` FROM `users` WHERE `email`='" + argument + "'\n AND `password`='" + password +"'"
        print(sql)
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

    # Error testing
    with connection.cursor() as cursor:
        # Read a single record
        argument = "webmaster@python.org' OR 1=1  "
        password = "0"
        sql = "SELECT `id`, `password` FROM `users` WHERE `email`='" + argument + "'\n AND `password`='" + password +"'"
        print(sql)
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)