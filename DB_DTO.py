from marshmallow import Schema, fields, EXCLUDE, ValidationError
from common import log
class ongs(Schema):
    id = fields.Integer(allow_none=True)
    dominio = fields.Str(required = True, error_messages={'required': 'An ong needs at least a name'})
    pais = fields.Str(allow_none=True)
    class Meta:
        unknown = EXCLUDE

def validate_with_DTO(table_name,object):
    try:
        validator_schema = get_correct_DTO(table_name)
        validator_schema.validate(object)
    except ValidationError as e:
        log(e)
        return False
    return True
def get_correct_DTO(table_name):
    schemas = {
        'ongs' : ongs()
    }
    return schemas[table_name]