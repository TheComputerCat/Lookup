DATA_DIR=$(shell echo $${DATA_DIR:-$(PWD)/data})
DOMAIN_LIST_PATH=$(shell echo $${DOMAIN_LIST_PATH:-$(DATA_DIR)/domains.csv})
SHODAN_API_KEY=$(shell echo $${SHODAN_API_KEY:-$(PWD)/shodan_api_key})
DB_CONFIG_FILE_PATH=$(shell echo $${DB_CONFIG_FILE_PATH:-$(PWD)/data_base_config.ini})

SHODAN_DOMAIN_DATA_FOLDER=$(DATA_DIR)/data_domain_shodan_raw/
ADDRESSES_LIST_FILE_PATH=$(DATA_DIR)/addresses.csv
SHODAN_HOST_DATA_FOLDER=$(DATA_DIR)/data_host_shodan/    
NMAP_HOST_DATA_FOLDER=$(DATA_DIR)/data_host_nmap/

build:
	python3 -m src.main $(DATA_DIR) $(DOMAIN_LIST_PATH)  $(SHODAN_API_KEY) $(DB_CONFIG_FILE_PATH)

domain-lookup:
	python3 -m src.lookup.domain_lookup lookup $(DOMAIN_LIST_PATH) $(SHODAN_DOMAIN_DATA_FOLDER) $(SHODAN_API_KEY)

get-ip-addresses:
	python3 -m src.lookup.domain_lookup get_addresses $(ADDRESSES_LIST_FILE_PATH) $(SHODAN_DOMAIN_DATA_FOLDER)

host-lookup-shodan:
	python3 -m src.lookup.host_lookup shodan $(ADDRESSES_LIST_FILE_PATH) $(SHODAN_HOST_DATA_FOLDER) $(SHODAN_API_KEY)

host-lookup-nmap:
	sudo python3 -m src.lookup.host_lookup nmap $(ADDRESSES_LIST_FILE_PATH) $(NMAP_HOST_DATA_FOLDER)

create-db:
	python3 -m src.common.query_manager $(DB_CONFIG_FILE_PATH)

domain-extract:
	python3 -m src.extract.domain_extract $(DB_CONFIG_FILE_PATH) $(SHODAN_DOMAIN_DATA_FOLDER)

host-extract-shodan:
	python3 -m src.extract.host_extract $(DB_CONFIG_FILE_PATH) $(SHODAN_HOST_DATA_FOLDER)

host-extract-nmap:
	python3 -m src.extract.host_extract_nmap $(DB_CONFIG_FILE_PATH) $(NMAP_HOST_DATA_FOLDER)
	