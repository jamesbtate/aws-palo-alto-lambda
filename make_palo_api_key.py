#!/usr/bin/env python3
import configparser
import requests
import argparse
import urllib3
import logging
import boto3
import xml.etree.ElementTree as ET

import library


def get_api_key(firewall_ip, username, password):
    """ Make an API call with username/password to get a Palo API key.

    returns: the API key as a string or None
    """
    url = 'https://' + firewall_ip + '/api/'
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.get(url, params=params, timeout=5, verify=False)
    except requests.exceptions.SSLError:
        logging.error("SSL error against firewall %s", firewall_ip)
        return None
    if response.status_code == 403:
        logging.error("HTTP 403 Unauthorized on firewall %s", firewall_ip)
        logging.debug("Response text: %s", response.text)
        return None
    if response.status_code == 200:
        logging.debug("HTTP 200: %s", response.text)
        # sample response text: <response status = 'success'><result><key>ab..
        #     ...weklHFZaKw==</key></result></response>
        try:
            root = ET.fromstring(response.text)
        except xml.etree.ElementTree.ParseError:
            logging.error("Error parsing XML response from firewall.")
            return None
        if root.tag != 'response' or 'status' not in root.attrib:
            logging.error('Malformed response: %s', response.text)
            return None
        status = root.attrib['status']
        if status != 'success':
            logging.error('keygen command not successful. status="%s"', status)
            return None
        try:
            key = root[0][0].text
        except IndexError:
            logging.error("Malformed successful response from firewall.")
            return None
        return key


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    parser = argparse.ArgumentParser(description="Make Palo API key")
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    config = library.read_config()
    username = config['username']
    password = config['password']
    firewall_ip = config['firewall_ip']
    key = get_api_key(firewall_ip, username, password)
    print('New API key:', key)


if __name__ == '__main__':
    main()
