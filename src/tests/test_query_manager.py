import unittest
import src.common.model as model
import src.common.query_manager as query_manager

from sqlalchemy import create_engine
from testcontainers.postgres import PostgresContainer
from unittest.mock import (
    patch,
    Mock,
)
from src.common.common import (
    createFixture,
    setUpWithATextFile,
    tearDownWithATextFile
)
    
withAFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestSetters(unittest.TestCase):
    def test_setConfigFile_withAUnexistentFile(self):
        """
            Given a path to a unexistent file, a exception must be raised.
        """
        with self.assertRaises(Exception) as cm:
            query_manager.setConfigFile('./pathToNothing')
        exception = cm.exception
        self.assertEqual(str(exception), './pathToNothing file do not exist')

    @withAFile(pathToTextFile = './myConfig.ini', content='')
    def test_setConfigFile_withAExistentFile(self, pathToTextFile):
        """
            Given a path to a existent file, the global containing the path must be
            updated.
        """

        query_manager.setConfigFile(pathToTextFile)
        self.assertEqual(query_manager.CONFIG_FILE_PATH, pathToTextFile)

class TestGetDBEngine(unittest.TestCase):
    pathToFile = './myConfig.ini'
    fileContent = """
        [default]
        host = localhost
        port = 5432
        database = postgres
        [credentials]
        username = postgresusr
        password = complex_password
    """

    def setPath(pathToConfig):
        query_manager.CONFIG_FILE_PATH = pathToConfig
    def clearPath():
        query_manager.CONFIG_FILE_PATH = None

    withConfigPatSetTo = createFixture(setPath, clearPath)

    @withAFile(pathToTextFile = pathToFile, content=fileContent)
    @withConfigPatSetTo(pathToConfig=pathToFile)
    @patch('src.common.query_manager.create_engine', new_callable=Mock, wraps=query_manager.create_engine)
    @patch('src.common.query_manager.getConfig', new_callable=Mock, wraps=query_manager.getConfig)
    def test_getDBEngine_withAExistentFile(self, spyGetConfig, spyCreate_engine):
        """
            Given a configuration path CONFIG_FILE_PATH set to that path, 
            create_engine should be called with the correct credentials 
            and configurations.
        """
        query_manager.getDBEngine()
        spyGetConfig.assert_called_once()
        spyCreate_engine.assert_called_once_with(
            'postgresql+psycopg2://postgresusr:complex_password@localhost:5432/postgres',
            echo=False,
            executemany_mode='values_plus_batch'
        )

    @withConfigPatSetTo(pathToConfig=None)
    def test_getDBEngine_withAUnexistentFile(self):
        """
            With CONFIG_FILE_PATH not set, an exception should be raised.
        """
        with self.assertRaises(Exception) as cm:
            query_manager.getDBEngine()
        exception = cm.exception
        self.assertEqual(str(exception), 'CONFIG_FILE_PATH is not set')

class TestTablesCreation(unittest.TestCase):
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, return_value='anEngineObject')
    @patch('src.common.query_manager.Base.metadata.create_all', new_callable=Mock)
    def test_createTables_createTablesFromScratch(self, mockCreateAll, mockGetDBEngine):
        """
            Given the model for the database, the correspondent tables
            are created in the database
        """

        query_manager.createTables()
        mockCreateAll.assert_called_once_with('anEngineObject')

def setUpDatabase(postgres, pathConfig):
    postgres.start()
    query_manager.setConfigFile(pathConfig)
    query_manager.createTables()

def tearDownDatabase(postgres):
    postgres.stop()

withTestDatabase = createFixture(setUpDatabase, tearDownDatabase)

class TestGetOrCreate(unittest.TestCase):
    pathConfig = './myConfig.ini'
    postgresContainer = PostgresContainer("postgres:latest")
    credentials ="""
        [default]
        host = localhost
        port = 5432
        database = postgres
        [credentials]
        username = postgresusr
        password = complex_password
        """

    def getDBEngineStub(postgresContainer):
        def _():
            return create_engine(postgresContainer.get_connection_url())
        return _
    
    @withAFile(pathToTextFile = pathConfig, content=credentials)
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withTestDatabase(postgres=postgresContainer, pathConfig=pathConfig)
    def test_getOrCreate_tablesNotFilled(self, mockCreateEngine):
        """
            Given a database with the tables specified in the model created, and no rows.
            When getOrCreate is called.
            Then the new object is inserted and returned.
        """
        host1 = model.Host(address='8.8.8.8')
        createdHost = query_manager.getOrCreate(model.Host, host1)
        self.assertEqual(createdHost, model.Host(address='8.8.8.8'))

        mainDomain1 = model.MainDomain(name='somedomain.org')
        createdMainDomain = query_manager.getOrCreate(model.MainDomain, mainDomain1)
        self.assertEqual(createdMainDomain, model.MainDomain(id=1, name='somedomain.org'))

        domainInfo1 = model.DomainInfo(domain='someSubdomain.org', subdomain=False, main_domain_id=1)
        createdDomainInfo = query_manager.getOrCreate(model.DomainInfo, domainInfo1)
        self.assertEqual(createdDomainInfo, model.DomainInfo(id=1, domain='someSubdomain.org', subdomain=False, main_domain_id=1))

    def withSomeColumnsSetUp():
        host1 = model.Host(address='8.8.8.8')
        query_manager.insert(host1)
        mainDomain1 = model.MainDomain(name='somedomain.org')
        query_manager.insert(mainDomain1)
        domainInfo1 = model.DomainInfo(domain='someSubdomain.org', subdomain=False, main_domain_id=1)
        query_manager.insert(domainInfo1)
        host2 = model.Host(address='4.4.4.4')
        query_manager.insert(host2)
        mainDomain2 = model.MainDomain(name='someotherdomain.org')
        query_manager.insert(mainDomain2)
        domainInfo2 = model.DomainInfo(domain='someotherSubdomain.org', subdomain=False, main_domain_id=1)
        query_manager.insert(domainInfo2)

    withSomeColumnsInserted = createFixture(withSomeColumnsSetUp, None)

    @withAFile(pathToTextFile = pathConfig, content=credentials)
    @patch('src.common.query_manager.getDBEngine', new_callable=Mock, side_effect=getDBEngineStub(postgresContainer))
    @withTestDatabase(postgres=postgresContainer, pathConfig=pathConfig)
    @withSomeColumnsInserted()
    def test_getOrCreate_tablesFilled(self, mockCreateEngine):
        """
            Given a database with the tables specified in the model created, and some rows inserted.
            When getOrCreate is called.
            Then the new object is inserted and returned.
        """
        host2 = model.Host(address='4.4.4.4')
        createdHost = query_manager.getOrCreate(model.Host, host2)
        self.assertEqual(createdHost, model.Host(address='4.4.4.4'))

        mainDomain2 = model.MainDomain(name='someotherdomain.org')
        createdMainDomain = query_manager.getOrCreate(model.MainDomain, mainDomain2)
        self.assertEqual(createdMainDomain, model.MainDomain(id=2, name='someotherdomain.org'))

        domainInfo2 = model.DomainInfo(domain='someotherSubdomain.org', subdomain=False, main_domain_id=1)
        createdDomainInfo = query_manager.getOrCreate(model.DomainInfo, domainInfo2)
        self.assertEqual(createdDomainInfo, model.DomainInfo(id=2, domain='someotherSubdomain.org', subdomain=False, main_domain_id=1))

if __name__ == '__main__':
    unittest.main()