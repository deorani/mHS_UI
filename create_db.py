import sqlite3
from config import admin_user

database = "users.db"
create_user_table = """ CREATE TABLE IF NOT EXISTS user (
                                id integer PRIMARY KEY,
                                email text NOT NULL,
                                username text NOT NULL,
                                password_hash text,
                                authenticated integer,
                                admin integer
                            ); """

insert_admin_user = """INSERT INTO
                             user(email,
                                  username,
                                  password_hash,
                                  authenticated,
                                  admin
                                  )
                            VALUES(:email,
                                   :username,
                                   :password_hash,
                                   :authenticated,
                                   :admin
                                   )
                            ;"""


conn = sqlite3.connect(database)
cursor = conn.cursor()
cursor.execute(create_user_table)
cursor.execute(insert_admin_user, admin_user)
conn.commit()
