DATA_DIR=$(shell echo $${DATA_DIR:-$(PWD)/data})
DOMAIN_LIST_PATH=$(shell echo $${DOMAIN_LIST_PATH:-$(DATA_DIR)/domains.csv})
SHODAN_API_KEY=$(shell echo $${SHODAN_API_KEY:-$(PWD)/shodan_api_key})
DB_CONFIG_FILE_PATH=$(shell echo $${DB_CONFIG_FILE_PATH:-$(PWD)/data_base_config.ini})
build:
	python3 -m src.main $(DATA_DIR) $(DOMAIN_LIST_PATH)  $(SHODAN_API_KEY) $(DB_CONFIG_FILE_PATH)