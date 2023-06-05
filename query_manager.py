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
from copy import deepcopy
import sys

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

def insert(TableObject, session=None):
    closeSession = False
    if not session:
        session = getDBSession()
        closeSession = True
    try:
        session.add(TableObject)
        session.commit()
    except Exception as e:
        log(e, debug=True, printing=True) 
        session.rollback()
    finally:
        if closeSession:
            session.close()

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
        found = session.query(classObject).filter_by(**dict).first()
        session.expunge_all()
        return found

def queryHost(session, object):
    return session.query(Host).where(Host.address == object.address).one_or_none()

def queryMainDomain(session, object):
    return session.query(MainDomain).where(MainDomain.name == object.name).one_or_none()

def queryDomainInfo(session, object):
    return session.query(DomainInfo).where(DomainInfo.domain == object.domain).one_or_none()

QUERIES = {
    Host: queryHost,
    MainDomain: queryMainDomain,
    DomainInfo: queryDomainInfo
}

def getQuery(classObject):
    return QUERIES[classObject]

def getOrCreate(classObject, object):
    with getDBSession() as session:
        query = getQuery(classObject)
        instance = query(session, object)
        if instance:
            return instance
        else:
            insert(deepcopy(object), session)
            instance = query(session, object)
            return instance
def getAllFromClass(classObject):
    with getDBSession() as session:
        query = session.query(classObject).all()
        session.close()
        return query

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) < 1:
        raise Exception("""Este archivo crea las tablas en la base de datos. Necesita un argumento:
    - La ruta al archivo de credenciales para acceder a la base de datos.""")

    setConfigFile(common.formatFilePath(args[0]))
    createTables()