"""
stuff
"""

import configparser


def read_config(filename='config.ini', section='default'):
    """ Reads a config file and returns a section of it. """
    config = configparser.ConfigParser()
    config.read(filename)
    return config[section]
