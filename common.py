import datetime
def log(message, logPath="./data/log", debug=False):
    if debug:
        return
    try:
        f = open(logPath, "a")
        logMessage = "{} : {}\n\n".format(datetime.datetime.now(), message)
        f.write(logMessage)
        f.close()
        print(logMessage)
    except Exception as e:
        print(e)
