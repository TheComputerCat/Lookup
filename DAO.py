from datetime import (
    datetime,
)

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

from sqlalchemy.orm import (
    DeclarativeBase,
    mapped_column,
    Mapped,
    relationship,
)

from typing import (
    List,
    Optional,
)

import urllib.parse

metadata_obj = MetaData()
class Base(DeclarativeBase):
    pass

class Host(Base):
    __tablename__ = "HOSTS"

    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(String(15))

    services_in_host: Mapped[List["HostService"]] = relationship(back_populates="host")

class Service(Base):
    __tablename__ = "SERVICES"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=True)

    cpe_code: Mapped["CPECode"] = relationship(back_populates="service")
    hosts_with_service: Mapped[List["HostService"]] = relationship(back_populates="service")

class HostService(Base):
    __tablename__ = "HOST_SERVICES"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("HOSTS.id"), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey("SERVICES.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    host: Mapped[Host] = relationship(back_populates="services_in_host")
    service: Mapped[Service] = relationship(back_populates="hosts_with_service")

class CPECode(Base):
    __tablename__ = "CPE_CODES"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(100), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey("SERVICES.id"), nullable=False)

    service: Mapped[Service] = relationship(back_populates="cpe_code")
