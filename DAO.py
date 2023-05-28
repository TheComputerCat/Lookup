from datetime import (
    datetime,
)

from sqlalchemy import (
    create_engine,
    DateTime,
    ForeignKey,
    String,
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

class Base(DeclarativeBase):
    pass

class Organization(Base):
    __tablename__ = "ORGANIZATIONS"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=True)

    domains: Mapped[List["Domain"]] = relationship(back_populates="organization")

class Domain(Base):
    __tablename__ = "DOMAINS"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[int] = mapped_column(ForeignKey("ORGANIZATIONS.id"), nullable=True)

    organization: Mapped[Optional[Organization]] = relationship(back_populates="domains")
    a_records: Mapped[List["ARecord"]] = relationship(back_populates="parent_domain")
    mx_records: Mapped[List["MXRecord"]] = relationship(back_populates="parent_domain")
    mx_records_with_domain: Mapped[List["MXRecord"]] = relationship(back_populates="domain")
    txt_records: Mapped[List["TXTRecord"]] = relationship(back_populates="parent_domain")

class Host(Base):
    __tablename__ = "HOSTS"

    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(String(15))

    services_in_host: Mapped[List["HostService"]] = relationship(back_populates="host")
    a_records_with_host: Mapped[List["ARecord"]] = relationship(back_populates="address")

class ARecord(Base):
    __tablename__ = "A_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    parent_domain_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS.id"), nullable=False)
    address_id: Mapped[int] = mapped_column(ForeignKey("HOSTS.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain: Mapped[Domain] = relationship(back_populates="a_records")
    address: Mapped[Host] = relationship(back_populates="a_records_with_host")

class MXRecord(Base):
    __tablename__ = "MX_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    parent_domain_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS.id"), nullable=False)
    domain_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain: Mapped[Domain] = relationship(back_populates="mx_records")
    domain: Mapped[Domain] = relationship(back_populates="mx_records_with_domain")

class TXTRecord(Base):
    __tablename__ = "TXT_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    parent_domain_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS.id"), nullable=False)
    content: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain: Mapped[Domain] = relationship(back_populates="txt_records")

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
