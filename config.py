import pymysql

# Database connection settings
DB_HOST = 'ammu'
DB_USER = 'root'
DB_PASSWORD = 'root'  # Replace with your MySQL root password
DB_NAME = 'cve_data'

def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )
