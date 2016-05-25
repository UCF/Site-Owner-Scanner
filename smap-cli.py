#!/usr/bin/env python
# -*- coding: utf-8 -*-

from contextlib import contextmanager

from core import settings
from core.models import Base
from core.models import DNSList
from core.models import IPRange
from core.parser import Parser
from core.scanner import Scanner

from core.cli.output import display_failure
from core.cli.output import display_info
from core.cli.output import display_warning

from sqlalchemy.sql import exists
from sqlalchemy.engine import reflection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine.url import URL

from sqlalchemy_utils import database_exists

import click
import mimetypes
import os
import sqlalchemy
import sys

Engine = sqlalchemy.create_engine(
    URL(**settings.DATABASE), echo=settings.DEBUG)
Session = sessionmaker(bind=Engine)


@contextmanager
def session_scope():
    session = Session()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as sql_error:
        display_failure(
            '{0}'.format(str(sql_error)))
        session.rollback()
        sys.exit(1)
    finally:
        session.close()


def banner():
    print r"""

 ________  _____ ______   ________  ________
|\   ____\|\   _ \  _   \|\   __  \|\   __  \
\ \  \___|\ \  \\\__\ \  \ \  \|\  \ \  \|\  \
 \ \_____  \ \  \\|__| \  \ \   __  \ \   ____\
  \|____|\  \ \  \    \ \  \ \  \ \  \ \  \___|
    ____\_\  \ \__\    \ \__\ \__\ \__\ \__\
   |\_________\|__|     \|__|\|__|\|__|\|__|
   \|_________|

---- [ version {0} D.Ford <Demetrius.Ford@ucf.edu> ] ----

    """.format(settings.VERSION)


def inspect_csv(ctx, param, value):
    mimetype = mimetypes.guess_type(value, strict=True)[0]
    extension = mimetypes.guess_extension(mimetype, strict=True)

    if mimetype != 'text/csv' or extension != '.csv':
        display_failure("'{0}' is not a CSV file.".format(value))
        sys.exit(1)

    fsize = os.stat(value).st_size
    if not fsize >= 0 and fsize <= settings.MAX_BYTES:
        converted = settings.MAX_BYTES * 0.001
        display_failure(
            "CSV doesn't meet size requirements {0}K.".format(converted))
        sys.exit(1)
    return value


@click.group()
@click.version_option(version=settings.VERSION)
def smap():
    """Map UCF Site Owners."""


@smap.command()
def scan():
    if not database_exists(Engine.url):
        display_failure('database does not exist.')
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)

    if not inspector.get_table_names():
        display_failure('no table(s) were found.')
        sys.exit(1)

    with session_scope() as session:
        q1 = session.query(DNSList)
        q2 = session.query(IPRange)

        if not(session.query(q1.exists()).scalar()
               and session.query(q2.exists()).scalar()):
            display_failure(
                'scan requires records in both `dns_list` and `ip_range`.')
            sys.exit(1)

        banner()
        display_info('starting scan ...')
        Scanner().scan(session)
    return 0


@smap.command()
def setupdb():
    if not database_exists(Engine.url):
        display_failure('database does not exist.')
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)

    if not inspector.get_table_names():
        Base.metadata.create_all(Engine, checkfirst=True)
        display_info('created database tables.')
        return 0

    display_warning('skipped. Table(s) already exist.')
    return 0


@smap.command('insert-dns-records')
@click.option('--target', type=click.Path(exists=True), callback=inspect_csv)
def insert_dns_records(target):
    if not database_exists(Engine.url):
        display_failure('database does not exist.')
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)
    required = ('ip',
                'firewall_map',
                'domain',
                'dns_record',
                'dns_list')

    missing_tables = [
        i for i in required if i not in inspector.get_table_names()]

    if missing_tables:
        display_failure(
            'missing table(s) -> {0}'.format(', '.join(missing_tables)))
        sys.exit(1)

    with session_scope() as session:
        Parser().parse_dns_records(target, session)
    return 0


@smap.command('insert-domain-info')
@click.option('--target', type=click.Path(exists=True), callback=inspect_csv)
def insert_domain_info(target):
    if not database_exists(Engine.url):
        display_failure('database does not exist.')
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)
    if 'ip_range' not in inspector.get_table_names():
        display_failure("`ip_range` table doesn't exist.")
        sys.exit(1)

    with session_scope() as session:
        Parser().parse_domain_info(target, session)
    return 0

if __name__ == '__main__':
    sys.exit(smap())
