#!/usr/bin/env python
# -*- coding: utf-8 -*-

from contextlib import contextmanager

from core import settings
from core.models import Base
from core.parser import Parser
from core.scanner import Scanner

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


def welcome():
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
        msg = str(error)
        click.echo('ERROR: {0}'.format(msg), file=sys.stderr)
        session.rollback()
        sys.exit(1)
    finally:
        session.close()


def is_csv(ctx, param, value):
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
    welcome()
    click.echo('[*] starting scan ...')
    with session_scope() as session:
        Scanner().scan(session)


@smap.command()
def setupdb():
    """Create database tables if needed."""
    if not database_exists(Engine.url):
        click.echo('ERROR: database does not exist.')
        sys.exit(1)

    inspector = reflection.Inspector.from_engine(Engine)
    if not any(inspector.get_table_names()):
        Base.metadata.create_all(Engine, checkfirst=True)
        click.echo('[+] created database tables.')
        return
    
    click.echo('WARNING: skipped. Table(s) already exist.')


@smap.command('insert-dns-records')
@click.option('--target', type=click.Path(exists=True), callback=is_csv)
def insert_dns_records(target):
    """Insert DNS records to database."""
    with session_scope() as session:
        Parser().parse_dns_records(target, session)


@smap.command('insert-domain-info')
@click.option('--target', type=click.Path(exists=True), callback=is_csv)
def insert_domain_info(target):
    """Insert IPMan records to database."""
    with session_scope() as session:
        Parser().parse_domain_info(target, session)

if __name__ == '__main__':
    sys.exit(smap())
