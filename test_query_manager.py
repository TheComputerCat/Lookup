import unittest
import query_manager
import json

from unittest.mock import (
    patch,
    Mock,
)

from common import (
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
    @patch('query_manager.create_engine', new_callable=Mock, wraps=query_manager.create_engine)
    @patch('query_manager.getConfig', new_callable=Mock, wraps=query_manager.getConfig)
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
    @patch('query_manager.getDBEngine', new_callable=Mock, return_value='anEngineObject')
    @patch('query_manager.Base.metadata.create_all', new_callable=Mock)
    def test_createTables_createTablesFromScratch(self, mockCreateAll, mockGetDBEngine):
        """
            Given the model for the database, the correspondent tables
            are created in the database
        """

        query_manager.createTables()
        mockCreateAll.assert_called_once_with('anEngineObject')

if __name__ == '__main__':
    unittest.main()