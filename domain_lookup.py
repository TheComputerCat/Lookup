import shodan

def getDomainsFromFile():
    with open("./data/domain_list",'r') as domains_file:
        domain_list = domains_file.read()
        return domain_list.split(",")

def getShodanInfoOf(domain: str):
    with open("shodan_api_key") as f:
        key = f.read()

    api = shodan.Shodan(key)
    return api.dns.domain_info(domain=domain, history=False, type=None, page=1)
