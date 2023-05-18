import datetime
import os

def log(message, logPath="./data/log", debug=False):
    if debug:
        raise message
    try:
        f = open(logPath, "a")
        logMessage = "{} : {}\n\n".format(datetime.datetime.now(), message)
        f.write(logMessage)
        f.close()
        print(logMessage)
    except Exception as e:
        print(e)

def getStringFromFile(path: str):
    try:
        f = open(path, "r")
        string = f.read()
        f.close()
    except Exception as e:
        log(e)
        return ""

    return string

def writeStringToFile(path: str, content: str, overwrite: bool=False):
    writeType = { False: "a", True: "w" }[overwrite]
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        f = open(path, writeType)
        f.write(content)
        f.close()
        return True
    except Exception as e:
        log(e)
        return False

def getTimeString():
    return datetime.datetime.now().strftime("-%Y:%m:%d-%H:%M:%S")