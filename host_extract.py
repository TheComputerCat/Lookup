from common import (
    log,
)

def getHostNamesFromDict(dict):
    try:
        return dict['hostnames']
    except Exception as e:
        log(e)
        return []