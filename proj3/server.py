import socket
import json
import random
from datetime import datetime
import hashlib
import sys

# function to print server log
def server_log(message):
    finalDateTime = (datetime.now()).strftime("%Y-%m-%d-%H-%M-%S")
    print(f"SERVER LOG:", finalDateTime, message)

# function to handle a POST request for user login:
def post(headers, account_file, serverSessions, cookies):

    # obtain "username" and "password" from request headers
    username = headers.get("username")
    password = headers.get("password")

    # if 1 or both fields missing:
    if not username or not password:
        server_log("LOGIN FAILED")
        return "501 Not Implemented", "", ""
    
    # if "username" and "password" are valid:
    if validate(account_file, username, password):
        # set-cookie called "sessionID" to a random 64-bit hexadecimal value
        sessionID = hex(random.getrandbits(64))
        header = "Set-Cookie: sessionID=" + sessionID

        # create a session with required info for validation using the cookie
        serverSessions[sessionID] = [username, datetime.now()] # server-side, DB of all cookies

        server_log("LOGIN SUCCESSFUL: " + str(username) + " : " + str(password))
        return "200 OK", header, "Logged in!"
    else:
        server_log("LOGIN FAILED: " + str(username) + " : " + str(password))
        return "200 OK", "Login failed!", ""

def validate(account_file, user, givenPass):
    # get salt and password from DB
    with open(account_file, 'r') as f:
        data = json.load(f)
    user = user.strip()
    try:
        userData = data[user] 
        password = userData[0]
        salt = userData[1]

        # compute salted hash
        combined_data = givenPass + salt
        combined_data = combined_data.encode('utf-8')
        sha256 = hashlib.sha256()
        sha256.update(combined_data)
        hashed_data = sha256.hexdigest()

        # compare salted hash against given password
        if hashed_data == password:
            return True
        else:
            return False
    except:
        return False

# function to handle a GET request for downloads:
def get(headers, session_timeout, root_directory, target, serverSessions, cookies):

    # obtain cookies from http request
    cookie = (cookies["sessionID"]).strip()

    # if cookies are missing
    if not cookie:
        return "401 Unauthorized", "", ""

    # if the "sessionID" cookie exists -- server-side
    try:

        # get username and timestamp info for that sessionID
        userData = serverSessions[cookie]
        user = userData[0]
        timeCreated = userData[1]

        timeDelta = datetime.now() - timeCreated
        # if timestamp within timeout period
        if timeDelta.total_seconds() < session_timeout:
            # update sessionID timestamp for the user to the current time
            serverSessions[cookie] = user, datetime.now()
            
            # if path to target exists
            target_path = root_directory + '/' + user + '/' + target
            try:
                with open(target_path, 'r') as f:
                    server_log("GET SUCCEEDED: " + str(user) + " : " + str(target))
                    fileContents = f.read()
                return "200 OK", "", fileContents
            except:
                server_log("GET FAILED: " + str(user) + " : " + str(target))
                return "404 NOT FOUND", "", ""
        # session expired
        else:
            serverSessions[cookie] = "" # cookie no longer valid if session timed out
            server_log("SESSION EXPIRED: " + str(user) + " : " + str(target))
            return "401 Unauthorized", "", ""
    except:
        server_log("COOKIE INVALID: " + str(target))
        return "401 Unauthorized", "", ""

# function to start the server:
def startServer(ip, port, account_file, session_timeout, root_directory):
    # create and bind a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    
    # start listening for incoming connections
    s.listen(5)

    serverSessions = {} # server-side DB to keep track of active cookies
    cookies = {} # hold cookies after parsing HTTP message

    while True:
        # accept incoming connection
        clientsocket, address = s.accept()
        # print(f"Connection from {address} has been established.")

        # receive an HTTP request from the client
        m = clientsocket.recv(1024).decode("utf-8")

        # extract the HTTP method, request target, and HTTP version
        lines = m.split('\r\n')
        start_line = lines[0]
        method, target, version = start_line.split(' ')
        headers = {}
        for header in lines[1:]:
            if header == "" or (not header):
                break # means we reached body
            hkey, hval = header.split(': ',1)
            if hkey == "Cookie":
                sessionID, realID = hval.split('=',1)
                cookies[sessionID] = realID
            else:
                headers[hkey] = hval
        if method == "POST" and target == "/":
            status, header, body = post(headers, account_file, serverSessions, cookies)
            response = f"HTTP/1.0 {status}\r\n{header}\r\n\r\n{body}"
        elif method == "GET":
            status, header, body = get(headers, session_timeout, root_directory, target, serverSessions, cookies)
            response = f"HTTP/1.0 {status}\r\n{header}\r\n\r\n{body}"
        else:
            status, header, body = "501 Not Implemented", "", ""
            response = f"HTTP/1.0 {status}\r\n{header}\r\n\r\n{body}"
        clientsocket.send(response.encode('utf-8'))
        clientsocket.close()
    
if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2])
    account_file = sys.argv[3]
    session_timeout = float(sys.argv[4])
    root_directory = sys.argv[5]
    startServer(ip, port, account_file, session_timeout, root_directory)