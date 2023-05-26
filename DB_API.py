import psycopg2
import json
from DB_DTO import validate_with_DTO
from common import (log, writeStringToFile, getDictFromJSONFile)


def _execute(query,return_results = False):
    try:
        credentials = getDictFromJSONFile('./data/DB_credentials.json')
        # Connect to the database
        connection = psycopg2.connect(**credentials)
        # Create a cursor object
        cursor = connection.cursor()
        cursor.execute(query)
        connection.commit()
        if return_results:
            return cursor.fetchall()
    except (Exception, psycopg2.DatabaseError) as error:
        log(error)
    finally:
        if connection is not None:
            cursor.close()
            connection.close()

# Define the CRUD functions
def insert_in(table_name, dict):
    if validate_with_DTO(table_name,dict):
        insert_statement = """
        INSERT INTO {table_name} ({columns}) VALUES ({values});
    """.format(
        table_name=table_name,
        columns=", ".join(dict.keys()),
        values=", ".join([str(value) for _, value in dict.items()])
    )
        _execute(insert_statement)
        writeStringToFile('./data/insertions',insert_statement)

