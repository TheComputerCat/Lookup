import unittest
import DB_API
import DB_DTO

from marshmallow import ValidationError
from common import (
    createFixture,
    writeStringToFile,
    setUpWithATextFile,
    tearDownWithATextFile,
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestValidateWithDTO(unittest.TestCase):
    def test_validate_true(self):
        isvalid = DB_DTO.validate_with_DTO('ongs',{
            'dominio': "pepe",
            'pais': 'colombia'})
        self.assertTrue(isvalid)

    def test_validate_allowing_missing_values(self):
        isvalid = DB_DTO.validate_with_DTO('ongs',{
            'dominio': "pepe"})
        self.assertTrue(isvalid)

    def test_validate_failing_missing_required_values(self):
        isvalid = DB_DTO.validate_with_DTO('ongs',{
            'pais': "colombia"})
        self.assertRaises(ValidationError)
    
    def test_validate_failing_wrong_type(self):
        isvalid = DB_DTO.validate_with_DTO('ongs',{
            'dominio': 1234 ,
            'pais': "colombia"})
        self.assertRaises(ValidationError)


if __name__ == '__main__':
     unittest.main()
