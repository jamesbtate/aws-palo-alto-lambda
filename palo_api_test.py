#!/usr/bin/env python3
import urllib
import ssl
import os
import logging
import xml.etree.ElementTree as ET
from botocore.exceptions import ClientError

import boto3
import requests
import urllib3
import argparse

import library


def get_firewall_status_paloalto(gwMgmtIp, api_key):
    """ Returns the status of the firewall.
    Calls the op command show chassis-ready.
    Requires an apikey and the IP address of the interface we send the
    API request to.

    :param gwMgmtIp:
    :param api_key:
    :return: 'running' or 'down'

    This is the function mostly un-modified from TransitGatewayRouteMonitor.py
    """

    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # cmd = urllib.request.Request('https://google.com')
    cmd = urllib.request.Request(
        "https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key)
    # Send command to fw and see if it times out or we get a response
    logging.info('[INFO]: Sending command: {}'.format(cmd))
    try:
        response = urllib.request.urlopen(cmd, data=None, context=gcontext, timeout=5).read()
        logging.info(
            "[INFO]:Got http 200 response from FW with address {}. So need to check the response".format(gwMgmtIp))
        # Now we do stuff to the gw
    except urllib.error.URLError:
        logging.info("[INFO]: No response from FW with address {}. So maybe not up!".format(gwMgmtIp))
        return 'down'
        # sleep and check again?
    else:
        logging.info("[INFO]: FW is responding!!")

    logging.info("[RESPONSE]: {}".format(response))
    resp_header = ET.fromstring(response)

    if resp_header.tag != 'response':
        logging.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'down'

    if resp_header.attrib['status'] == 'error':
        logging.info("[ERROR]: Got response header error for the command")
        return 'down'

    if resp_header.attrib['status'] == 'success':
        # The fw responded with a successful command execution
        for element in resp_header:
            if element.text.rstrip() == 'yes':
                # Call config gw command?
                logging.info("[INFO]: FW with ip {} is ready ".format(gwMgmtIp))
                return 'running'
    else:
        return 'down'


def get_firewall_status_james(firewall_ip, api_key):
    """ Get the status of the given firewall via HTTP API.

    returns: True for a healthy firewall, False otherwise.

    This is James's version of the PA FW health check.
    """
    url = 'https://' + firewall_ip + '/api/'
    params = {
        'type': 'op',
        'cmd': '<show><chassis-ready></chassis-ready></show>',
        'key': api_key
    }
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.get(url, params=params, timeout=5, verify=False)
    except requests.exceptions.SSLError:
        logging.error("SSL error against firewall %s", firewall_ip)
        return False
    logging.debug("Response code: %s", response.status_code)
    logging.debug("Response text: %s", repr(response.text))
    if response.status_code == 403:
        logging.error("HTTP 403 Unauthorized on firewall %s", firewall_ip)
        return False
    if response.status_code == 200:
        try:
            root = ET.fromstring(response.text)
        except:
            logging.error("Invalid XML response from firewall")
            return False
        if root.tag != 'response' or 'status' not in root.attrib:
            logging.error("Malformed response from firewall")
            return False
        try:
            message = root[0].text.strip()
        except:
            logging.error("Could not extract message from firewall response.")
            return False
        if message == 'yes':
            return True
        else:
            logging.warning("Unexpected chassis-ready from firewall: %s",
                            message)
            return False
    logging.error("Unhandled HTTP status code: %d", response.staus_code)
    return False


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logging.info("Started logger.")
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    config = library.read_config()
    api_key = config['api_key']
    firewall_ip = config['firewall_ip']
    status = get_firewall_status_paloalto(firewall_ip, api_key)
    print('paloalto returned status:', status)
    status = get_firewall_status_james(firewall_ip, api_key)
    print('james returned status:', status)


if __name__ == '__main__':
    main()
