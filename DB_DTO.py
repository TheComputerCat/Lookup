from marshmallow import Schema, fields, EXCLUDE, ValidationError
from common import log
class ORGS(Schema):
    domain = fields.Integer(required = True)
    class Meta:
        unknown = EXCLUDE

class A_RECORDS(Schema):
    address = fields.Integer(required = True)
    parent_domain = fields.Integer(required = True)
    time = fields.DateTime(required = True)
    class Meta:
        unknown = EXCLUDE

class DOMAINS(Schema):
    name = fields.String(allow_none=True)
    subdomain = fields.Boolean(required=True)
    org = fields.Integer(allow_none=True, required=True)
    class Meta:
        unknown = EXCLUDE

class HOSTS(Schema):
    address = fields.String(required=True)
    class Meta:
        unknown = EXCLUDE

class MX_RECORDS(Schema):
    value = fields.String(required = True)
    subdomain = fields.Boolean(required = True)
    parent_domain = fields.Integer(required = True)
    time = fields.DateTime(required = True)
    class Meta:
        unknown = EXCLUDE

class SERVICES(Schema):
    name = fields.String(required=True)
    version = fields.String(allow_none=True)

class HOST_SERVICES(Schema):
    host = fields.Integer(required=True)
    service = fields.Integer(required=True)
    timestamp = fields.DateTime(required=True)
    port = fields.Integer(required=True)

class CPE_CODES(Schema):
    code = fields.String(required=True)
    service = fields.Integer(required=True)

def validate_with_DTO(table_name,dict):
    try:
        validator_schema = get_correct_DTO(table_name)
        validator_schema.load(dict)
        return True
    except (ValidationError, Exception) as e:
        log(e)
        return False

def get_correct_DTO(table_name):
    return globals()[table_name]()
