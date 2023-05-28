from sqlalchemy import (
    create_engine,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
)

import urllib.parse

metadata_obj = MetaData()

hosts_table = Table(
    "HOSTS",
    metadata_obj,
    Column("id", Integer, primary_key=True),
    Column("address", String(15), nullable=False)
)

services_table = Table(
    "SERVICES",
    metadata_obj,
    Column("id", Integer, primary_key=True),
    Column("name", String(100), nullable=True),
    Column("version", String(100), nullable=True)
)

cpe_codes_table = Table(
    "CPE_CODES",
    metadata_obj,
    Column("id", Integer, primary_key=True),
    Column("code", String(100), nullable=False),
    Column("service", ForeignKey("SERVICES.id"), nullable=False)
)

host_services_table = Table(
    "HOST_SERVICES",
    metadata_obj,
    Column("id", Integer, primary_key=True),
    Column("host", ForeignKey("HOSTS.id"), nullable=False),
    Column("service", ForeignKey("SERVICES.id"), nullable=True),
    Column("timestamp", DateTime, nullable=False),
    Column("port", Integer, nullable=False),
    Column("source", String(30), nullable=False)
)
