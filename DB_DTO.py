from marshmallow import Schema, fields, EXCLUDE, ValidationError
from common import log
class ORGS(Schema):
    id = fields.Integer(allow_none=True)
    domain = fields.String(required = True)
    class Meta:
        unknown = EXCLUDE

class A_RECORDS(Schema):
    id = fields.Integer(allow_none=True)

class DOMAINS(Schema):
    id = fields.Integer(allow_none=True)

def validate_with_DTO(table_name,dict):
    try:
        validator_schema = get_correct_DTO(table_name)
        validator_schema.load(dict)
        return True
    except (ValidationError, Exception) as e:
        log(e)
        return False

def get_correct_DTO(table_name):
    schemas = {
        'ORGS' : ORGS()
    }
    return schemas[table_name]
