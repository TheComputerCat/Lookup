import datetime
import inspect
import os
import json
from collections.abc import Callable


def log(message, logPath="./log", debug=False, printing=False, testing=True):
    if debug:
        raise message
    try:
        f = open(logPath, "a")
        logMessage = "{} : {}\n\n".format(datetime.datetime.now(), message)
        f.write(logMessage)
        f.close()
        if printing and not testing:
            print(logMessage)
    except Exception as e:
        print(e)

def tryTo(fun: Callable, default, log=False):
    try:
        return fun()
    except Exception as e:
        if log:
            log(e)
        return default

def getFilePathsInDirectory(directoryPath):
    fixedDirPath = formatDirPath(directoryPath)

    return [
        fixedDirPath+fileName for fileName in sorted(os.listdir(fixedDirPath))
        if os.path.isfile(fixedDirPath+fileName)
    ]

def getStringFromFile(path: str):
    try:
        f = open(path, "r")
        string = f.read()
        f.close()
    except Exception as e:
        log(e, printing=True)
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
        log(e, printing=True)
        return False

def getTimeString():
    return datetime.datetime.now().strftime("-%Y:%m:%d-%H:%M:%S")

def asHexString(string: str):
    return string.encode("utf-8").hex()

def formatDirPath(dirPath):
    if dirPath[-1] != '/':
        return dirPath+'/'
    
    return dirPath

def formatFilePath(filePath):
    if filePath[-1] == '/':
        return filePath[:-1]
    
    return filePath

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

def setUpWithATextFile(pathToTextFile, content):
    writeStringToFile(pathToTextFile, content)

def tearDownWithATextFile(pathToTextFile, deleteFolder=True):
    os.remove(pathToTextFile)
    dirname = os.path.dirname(pathToTextFile)
    
    if(deleteFolder and dirname != '.' and dirname != os.getcwd() and len(os.listdir(dirname)) == 0):
        os.removedirs(dirname)

def removeFile(pathToTextFile):
    os.remove(pathToTextFile)
 
def getDictFromJSONFile(path: str):
    try:
        object = json.loads(getStringFromFile(path))
    except Exception as e:
        log(e, printing=True)
        return {}

    return object

def eqCreator(aClass, exceptions=[]):
    nonSpecialMembers = [a for a in inspect.getmembers(aClass) if not a[0].startswith('_')]
    withoutExceptions = [a[0] for a in nonSpecialMembers if a[0] not in exceptions]
    def eq(self, other):
        if not isinstance(other, aClass):
            return NotImplemented
        
        for attribute in withoutExceptions:
            if getattr(self, attribute) != getattr(other, attribute):
                return False
        return True
    return eq

def repCreator(aClass, exceptions=[]):
    nonSpecialMembers = [a for a in inspect.getmembers(aClass) if not a[0].startswith('_')]
    withoutExceptions = [a[0] for a in nonSpecialMembers if a[0] not in exceptions]
    def rep(self):
        attributesValue = [f'{attribute}={getattr(self, attribute)}' for attribute in withoutExceptions]
        return f'{aClass.__name__}({", ".join(attributesValue)})'
    return rep
