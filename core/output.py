# -*- coding: utf-8 -*-

import click
import sys


def display_info(message, prefix='[*] '):
    click.echo(click.style(prefix, fg='blue') + message)


def display_results(message, contains_errors=False):
    if contains_errors is True:
        click.echo(click.style('✖ ', fg='red') + message)
        return
    click.echo(click.style('✔ ', fg='green') + message)


def display_warning(message, separator=': ', label='WARNING'):
    click.echo(
        click.style(
            label,
            fg='yellow') +
        separator +
        message,
        file=sys.stderr)


def display_failure(message, separator=': ', label='ERROR'):
    click.echo(
        click.style(
            label,
            fg='red') +
        separator +
        message,
        file=sys.stderr)
