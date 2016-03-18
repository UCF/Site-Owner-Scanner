import click
import mimetypes
import random
import settings

from scanner import Scanner

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def is_csv(ctx, param, value):
    if mimetypes.guess_type(value, strict=True)[0] != 'text/csv':
        raise click.BadParameter('\'{0}\' is not a CSV file.'.format(value))
    return value


@click.command(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=settings.VERSION)
@click.argument('path', type=click.Path(exists=True), callback=is_csv)
def smap(path):
    click.echo('[*] scanning sites ...')
    Scanner(path).scan()

if __name__ == '__main__':
    smap()
