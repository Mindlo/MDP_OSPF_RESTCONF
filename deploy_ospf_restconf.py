import requests
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
import os
import logging

# Seet logging level
logging.basicConfig(level=logging.INFO)

# Disable SSL warnings
disable_warnings()

def process_template(template_name: str) -> bool:
    """
    process a JSON template of RESTCONF <PATCH> data.

    Args:
        template_name(str): The name of the JSON template to process

    Returns:
        result(bool): True if template is processed and False otherwise
    """

    try:
        with open("./device-templates/{}".format(template_name)) as fd:
            payload = fd.read()
    except OSError:
        logging.exception("Failed to open ./device-templates{}".format(device_name))
        return False
    
    # Template name must be DEVICE-NAME.json and the DEVICE-NAME must be available in the local DNS in /etc/hosts file
    device_name = template_name.rstrip(".json")
    logging.info("Deploying Template configuration to {}".format(device_name))

    url = "https://{}/restconf/data/Cisco-IOS-XE-native:native".format(device_name)

    creds = HTTPBasicAuth(
        username = os.environ["ROUTER_USERNAME"],
        password = os.environ["ROUTER_PASSWORD"]
    )


    headers = {
        "Content-Type":"application/yang-data+json"
    }

    try:
        response = requests.patch(
            url = url, auth = creds, headers = headers, data = payload, verify = False
        )

        if response.status_code == 204:
            logging.info("Successfully deployed configuration on {}".format(device_name))
    
    except Exception:
        logging.exception("Failed to deploy configuration on {}".format(device_name))
        return False
    
    return True


def main():
    """
    The main entrypoint of the script execution.
    This script will deploy configuration using restconf
    Restconf must be enabled on the target device beforehand
    Function will exit with Code 0 on success and Code 1 otherwise
    """

    result = True
    # Check through the device template directory that the files end with .json and then deploy config
    with os.scandir("./device-templates") as pd:
        for entry in pd:
            if entry.is_file() and entry.name.endswith(".json"):
                result &= process_template(entry.name) #logical AND operation

        if not result:
            exit(1)
if __name__== "__main__":
    main()
