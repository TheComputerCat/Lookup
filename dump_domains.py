class TypeARegisterRow(dict):
    def __init__(self, registerDict):
        self.address = registerDict["value"]
        
        if registerDict["subdomain"] == "":
            self.subdomain = None
        else:
            self.subdomain = registerDict["subdomain"]
        
        self.last_seen = registerDict["last_seen"]

def getDataAttrFromDict(dict):
    try:
        return dict["data"]
    except:
        return []

def getARegisters(dict):
    data = getDataAttrFromDict(dict)
    typeARegistersDicts = filter(
        lambda dict: "type" in dict and dict["type"] == "A",
        data
    )

    return [TypeARegisterRow(dict) for dict in typeARegistersDicts]
