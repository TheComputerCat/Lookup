from datetime import (
    datetime,
)

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    String,
    Boolean
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

class Base(DeclarativeBase):
    pass

class Organization(Base):
    __tablename__ = "ORGANIZATIONS"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=True)

    main_domains: Mapped[List["MainDomain"]] = relationship(back_populates="organization")

class MainDomain(Base):
    __tablename__ = "MAIN_DOMAINS"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[int] = mapped_column(ForeignKey("ORGANIZATIONS.id"), nullable=True)

    organization: Mapped[Organization] = relationship(back_populates="main_domains")
    domains_info: Mapped[List["DomainInfo"]] = relationship(back_populates="main_domain")

class DomainInfo(Base):
    __tablename__ = "DOMAINS_INFO"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    subdomain: Mapped[Boolean] = mapped_column(Boolean, nullable=False)
    main_domain_id: Mapped[int] = mapped_column(ForeignKey("MAIN_DOMAINS.id"), nullable=False)

    main_domain: Mapped[MainDomain] = relationship(back_populates="domains_info")
    a_records: Mapped[List["ARecord"]] = relationship(back_populates="parent_domain_info")
    mx_records: Mapped[List["MXRecord"]] = relationship(back_populates="parent_domain_info")
    txt_records: Mapped[List["TXTRecord"]] = relationship(back_populates="parent_domain_info")

class Host(Base):
    __tablename__ = "HOSTS"

    address: Mapped[str] = mapped_column(String(15), primary_key=True)
    country: Mapped[str] = mapped_column(String(2), nullable=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=True)
    isp: Mapped[str] = mapped_column(String(100), nullable=True)

    services_in_host: Mapped[List["HostService"]] = relationship(back_populates="host")
    a_records_with_host: Mapped[List["ARecord"]] = relationship(back_populates="address")

class ARecord(Base):
    __tablename__ = "A_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(ForeignKey("HOSTS.address"), nullable=False)
    parent_domain_info_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS_INFO.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain_info: Mapped[DomainInfo] = relationship(back_populates="a_records")
    address: Mapped[Host] = relationship(back_populates="a_records_with_host")

class MXRecord(Base):
    __tablename__ = "MX_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    parent_domain_info_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS_INFO.id"), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain_info: Mapped[DomainInfo] = relationship(back_populates="mx_records")

class TXTRecord(Base):
    __tablename__ = "TXT_RECORDS"

    id: Mapped[int] = mapped_column(primary_key=True)
    parent_domain_info_id: Mapped[int] = mapped_column(ForeignKey("DOMAINS_INFO.id"), nullable=False)
    content: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    parent_domain_info: Mapped[DomainInfo] = relationship(back_populates="txt_records")

class Service(Base):
    __tablename__ = "SERVICES"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=True)
    cpe_code: Mapped[str] = mapped_column(String(100), nullable=True)

    hosts_with_service: Mapped[List["HostService"]] = relationship(back_populates="service")
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(back_populates="service")

class Vulnerability(Base):
    __tablename__ = "VULNERABILITES"

    cve_code: Mapped[str] = mapped_column(String(100), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("SERVICES.id"), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    access_vector: Mapped[str] = mapped_column(String(10), nullable=False)
    access_complexity: Mapped[str] = mapped_column(String(10), nullable=False)
    authentication_requirement: Mapped[str] = mapped_column(String(10), nullable=False)
    confidentiality_impact: Mapped[str] = mapped_column(String(10), nullable=False)
    integrity_impact: Mapped[str] = mapped_column(String(10), nullable=False)
    availability_impact: Mapped[str] = mapped_column(String(10), nullable=False)

    service: Mapped[Service] = relationship(back_populates="vulnerabilities")


class HostService(Base):
    __tablename__ = "HOST_SERVICES"

    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(ForeignKey("HOSTS.address"), nullable=False)
    service_id: Mapped[int] = mapped_column(ForeignKey("SERVICES.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    host: Mapped[Host] = relationship(back_populates="services_in_host")
    service: Mapped[Service] = relationship(back_populates="hosts_with_service")
