import configparser
import os
from sqlalchemy import (create_engine, exc)
from sqlalchemy.orm import (
    Session
)

from common import (
    log
)
from model import *

CONFIG_FILE_PATH = None

def setConfigFile(configFilePath):
    global CONFIG_FILE_PATH
    try:
        if not os.path.exists(configFilePath):
            raise Exception(f'{configFilePath} file do not exist')
        CONFIG_FILE_PATH = configFilePath
    except Exception as e:
        log(e, debug=True, printing=True) 

def getConfig():
    config = configparser.ConfigParser()
    try:
        if CONFIG_FILE_PATH is None:
            raise Exception('CONFIG_FILE_PATH is not set')
        config.read(CONFIG_FILE_PATH)
        return config
    except Exception as e:
        log(e, debug=True, printing=True)

def getConnectionUrl():
    config = getConfig()
    host = config['default']['host']
    port = config['default']['port']
    database = config['default']['database']
    username = config['credentials']['username']
    password = config['credentials']['password']

    return f'postgresql+psycopg2://{username}:{password}@{host}:{port}/{database}'

def getDBEngine():
    return create_engine(getConnectionUrl(), echo=False, executemany_mode='values_plus_batch')

def getDBSession():
    return Session(getDBEngine())

def createTables():
    engine = getDBEngine()
    Base.metadata.create_all(engine)

def insert(TableObject):
    with getDBSession() as session:
        try:
            session.add(TableObject)
            session.commit()
        except Exception as e:
            log(e, debug=True, printing=True) 
        finally:
            session.rollback()

def insertMany(TableObjects):
    with getDBSession() as session:
        try:
            session.add_all(TableObjects)
            session.commit()
        except Exception as e:
            log(e, debug=True, printing=True) 
        finally:
            session.rollback()

def searchInTable(classObject, dict):
    with getDBSession() as session:
        try:
           found = session.query(classObject).filter_by(**dict).one()
           session.expunge_all()
           return found
        except (Exception,exc) as e:
            log(e, debug=True, printing=True) 
        finally:
            session.rollback()
