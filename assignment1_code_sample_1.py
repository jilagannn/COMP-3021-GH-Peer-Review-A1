import os
import pymysql
from urllib.request import urlopen
import json
import subprocess
import requests
import ssl

with open("db_config.json", "r") as data:
    db_config = json.load(data)

def get_user_input():
    user_input = input('Enter your name: ')
    return user_input

def send_email(to, subject, body):
    subprocess.run(
        ["mail", "-s", subject, to], 
        input=body, text=True, check=True)

def get_data():
    url = 'https://insecure-api.com/get-data'
    # we apply and enable TLS with this
    context = ssl.create_default_context()
    with urlopen(url=url, context=context) as data:
        return data

def save_to_db(data):
    # used parameter for variables instead of inputting variables 
    # directly into query
    query = f"INSERT INTO mytable (column1, column2) VALUES (%s, 'Another Value')"
    connection = pymysql.connect(**db_config)
    cursor = connection.cursor()
    cursor.execute(query, (data,))
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    user_input = get_user_input()
    data = get_data()
    save_to_db(data)
    send_email('admin@example.com', 'User Input', user_input)
