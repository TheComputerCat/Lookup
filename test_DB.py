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
        isvalid = DB_DTO.validate_with_DTO('ORGS',{
            'id':2,
            'domain': "pepe",})
        self.assertTrue(isvalid)

    def test_validate_allowing_missing_values(self):
        isvalid = DB_DTO.validate_with_DTO('ORGS',{
            'domain': "pepe"})
        self.assertTrue(isvalid)

    def test_validate_failing_missing_required_values(self):
        dict_to_validate = {'id': 27}
        isvalid = DB_DTO.validate_with_DTO('ORGS',dict_to_validate)
        self.assertRaises(ValidationError)
        self.assertFalse(isvalid)
    
    def test_validate_failing_wrong_type(self):
        dict_to_validate = {
            'domain': 1234, }
        isvalid = DB_DTO.validate_with_DTO('ORGS',dict_to_validate)
        self.assertRaises(ValidationError)
        self.assertFalse(isvalid)
    


if __name__ == '__main__':
     unittest.main()
