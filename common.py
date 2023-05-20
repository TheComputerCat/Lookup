import datetime
import inspect
import os

def log(message, logPath="./data/log", debug=False, testing = True):
    if debug:
        raise message
    try:
        f = open(logPath, "a")
        logMessage = "{} : {}\n\n".format(datetime.datetime.now(), message)
        f.write(logMessage)
        f.close()
        if not testing:
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

def asHexString(string: str):
    return string.encode("utf-8").hex()

def createFixture(setup, teardown):
    def decorator(**kwargsDecorator):
        def wrapper(function):
            def functionToTest(*args, **kargs):
                if setup:
                    setup(**filterKargsForFunction(setup, kwargsDecorator))
                try:
                    filterKargsDecorator = filterKargsForFunction(function, kwargsDecorator)
                    function(*args, **{**kargs, **filterKargsDecorator})
                finally:
                    if teardown:
                        teardown(**filterKargsForFunction(teardown, kwargsDecorator))
            return functionToTest
        return wrapper
    return decorator
            
def filterKargsForFunction(function, kargs):
    functionKargs = inspect.signature(function).parameters
    return { karg: kargs[karg] for karg in kargs if karg in functionKargs }