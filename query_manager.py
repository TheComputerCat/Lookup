from DAO import *
import configparser
from common import (
    log
)

from sqlalchemy.orm import (
    Session
)

from datetime import (
    datetime,
)


def getDBEngine():
    config = configparser.ConfigParser()
    config.read("data_base_config.ini")

    host = config['default']['host']
    port = config['default']['port']
    database = config['default']['database']
    username = config['credentials']['username']
    password = config['credentials']['password']

    return create_engine(f'postgresql://{username}:{password}@{host}:{port}/{database}', echo=True)

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
            log(e)
        finally:
            session.rollback()