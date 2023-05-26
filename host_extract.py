from common import (
    tryTo,
)

def getCountryCodeFromDict(dict):
    return tryTo(lambda: dict['country_code'], None)

def getHostNamesFromDict(dict):
    return tryTo(lambda: dict['hostnames'], [])

def getPortsFromDict(dict):
    return tryTo(lambda: dict['ports'], [])
