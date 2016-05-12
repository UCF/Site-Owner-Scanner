#!/usr/bin/env python
# -*- coding: utf-8 -*-

from contextlib import contextmanager

from core import settings
from core.models import Base
from core.models import DNSList
from core.models import IPRange
from core.parser import Parser
from core.scanner import Scanner

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


@contextmanager
def session_scope():
    """Yield session state in a controlled context."""
    session = Session()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as error:
        message = str(error)
        click.echo('ERROR: {0}'.format(message), file=sys.stderr)
        session.rollback()
        sys.exit(1)
    finally:
        session.close()


def inspect_csv(ctx, param, value):
    """Inspect CSV file to ensure it follows strict requirements."""
    mimetype = mimetypes.guess_type(value, strict=True)[0]
    extension = mimetypes.guess_extension(mimetype, strict=True)

    if mimetype != 'text/csv' or extension != '.csv':
        raise click.BadParameter('\'{0}\' is not a CSV file.'.format(value))

    fsize = os.stat(value).st_size
    if not fsize >= 0 and fsize <= settings.MAX_BYTES:
        raise click.BadParameter(
            'CSV doesn\'t meet size requirements {0}K.'.format(
                settings.MAX_BYTES * 0.001))
    return value


@click.group()
@click.version_option(version=settings.VERSION)
def smap():
    """Map UCF site owners."""


@smap.command()
def scan():
    """Start IP scanner."""
    if not database_exists(Engine.url):
        click.echo('ERROR: database does not exist.', file=sys.stderr)
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)
    if inspector.get_table_names():
        with session_scope() as session:
            q1 = session.query(DNSList)
            q2 = session.query(IPRange)
            if not(session.query(q1.exists()).scalar()
                   and session.query(q2.exists()).scalar()):
                click.echo(
                    'ERROR: missing Domain Ranges and DNS records!',
                    file=sys.stderr)
                return
            banner()
            click.echo('[*] starting scan ...')
            Scanner().scan(session)
    else:
        click.echo('ERROR: no table(s) were found.', file=sys.stderr)
        sys.exit(1)


@smap.command()
def setupdb():
    """Create smap database tables if needed."""
    if not database_exists(Engine.url):
        click.echo('ERROR: database does not exist.', file=sys.stderr)
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)
    if not inspector.get_table_names():
        Base.metadata.create_all(Engine, checkfirst=True)
        click.echo('[+] created database tables.')
        return

    click.echo('WARNING: skipped. Table(s) already exist.')


@smap.command('insert-dns-records')
@click.option('--target', type=click.Path(exists=True), callback=inspect_csv)
def insert_dns_records(target):
    """Insert DNS records to database."""
    with session_scope() as session:
        Parser().parse_dns_records(target, session)


@smap.command('insert-domain-info')
@click.option('--target', type=click.Path(exists=True), callback=inspect_csv)
def insert_domain_info(target):
    """Insert IPMan records to database."""
    with session_scope() as session:
        Parser().parse_domain_info(target, session)

if __name__ == '__main__':
    sys.exit(smap())
