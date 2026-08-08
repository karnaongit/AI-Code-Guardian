import os

def login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    db.execute(query)

def system_ping(ip):
    os.system("ping -c 4 " + ip)

def dynamic_eval(code):
    eval(code)
