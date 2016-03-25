from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import IPAddressType
from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import ForeignKey

Base = declarative_base()

class DNSList(Base):

    __tablename__ = 'dns_list'

    id = Column(Integer, primary_key=True)
    domain = Column(String, ForeignKey('domain.name'))
    record_type = Column(String, ForeignKey('dns_record.name'))
    dns_server = Column(IPAddressType, ForeignKey('dns_server.ip'))
    ext_ip = Column(IPAddressType)

class Domain(Base):

    __tablename__ = 'domain'

    id = Column(Integer, primary_key=True)
    name = Column(String)

class DNSRecord(Base):

    __tablename__ = 'dns_record'

    id = Column(Integer, primary_key=True)
    name = Column(String)

class DNSServer(Base):

    __tablename__ = 'dns_server'

    id = Column(Integer, primary_key=True)
    desc = Column(String)
    ip = Column(IPAddressType)
