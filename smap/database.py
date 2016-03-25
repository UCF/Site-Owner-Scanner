from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import IPAddressType
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text

from sqlalchemy.orm import relationship

Base = declarative_base()

class IP(Base):
    __tablename__ = 'ip'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(IPAddressType, nullable=False, unique=True)
    

class FirewallMap(Base):
    __tablename__ = 'firewall_map'
    
    id = Column(Integer, primary_key=True)
    internal_ip_id = Column(Integer, ForeignKey('ip.id'), nullable=False)
    external_ip_id = Column(Integer, ForeignKey('ip.id'), nullable=False)
    
    # Relationships
    internal_ip = relationship('IP', backref='firewall_maps')
    external_ip = relationship('IP', backref='firewall_maps')

class DNSList(Base):
    __tablename__ = 'dns_list'

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domain.id'), nullable=False)
    record_type_id = Column(Integer, ForeignKey('dns_record.id'), nullable=False)
    #dns_server = Column(IPAddressType, ForeignKey('dns_server.ip'))
    firewall_map_id = Column(Integer, ForeignKey('firewall_map.id'), nullable=False)
    
    # Relationships
    domain = relationship('Domain', backref='dns_lists')
    record_type = relationship('DNSRecordType', backref='dns_lists')
    firewall_map = relationship('FirewallMap', backref='dns_lists')

class Domain(Base):
    __tablename__ = 'domain'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    
class DNSRecordType(Base):
    __tablename__ = 'dns_record'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)

class DNSServer(Base):

    __tablename__ = 'dns_server'

    id = Column(Integer, primary_key=True)
    desc = Column(Text, nullable=True)
    ip = Column(IPAddressType, nullable=False)

class IPRange(Base):
    __tablename__ = 'ip_range'
    
    id = Column(Integer, primary_key=True)
    start_ip = Column(IPAddressType, nullable=False)
    end_ip = Column(IPAddressType, nullable=False)
    desc = Column(Text, nullable=True)
    owner_email = Column(String(255), nullable=False)

class ScanResult(Base):
    __tablename__ = 'scan_result'
    
    id = Column(Integer, primary_key=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    ip_id = Column(Integer, ForeignKey('ip.id'), nullable=False)
    domain_id = Column(Integer, ForeignKey('domain.id'), nullable=False)
    
    # Relationships
    ip = relationship('IP', backref='scan_results')
    domain = relationship('Domain', backref='scan_results')
    
    
class ScanInstance(Base):
    __tablename__ = 'scan_instance'
    
    id = Column(Integer, primary_key=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    author = Column(String(255), nullable=False)
