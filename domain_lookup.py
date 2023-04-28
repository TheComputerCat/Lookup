import shodan

def getShodanInfoFrom(domain: str):
    with open("shodan_api_key") as f:
        key = f.read()

    api = shodan.Shodan(key)
    return api.dns.domain_info(domain=domain, history=False, type=None, page=1)
    #we could just use this func instead of doing a new one...
