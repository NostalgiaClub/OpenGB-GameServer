
"""
        with open("map_data.json",  encoding="utf8") as map_data_text:
            return json.load(map_data_text)
"""

import sys
import os
import logging

import json

from GameServer.settings import ApplicationSettings
from GameServer.app import Application

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG
)


logger = logging.getLogger("Launcher")

json_file_name = os.environ.get('SETTINGS_JSON', 'settings.json')

if os.path.isfile(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        json_file_name)):
    logger.info("Settings File [{}] File Found".format(json_file_name))

    json_data: dict = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), json_file_name)))
else:
    logging.info("No JSON File Found. Loading Settings from Environment Variables")
    json_data: None = None

del json_file_name

if os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'map_data.json')):
    logger.info("Loading map_data.json")
    map_data = json.load(open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'map_data.json'),
        encoding="utf8"
    ))
else:
    raise ImportError("Failed to load map_data.json")


application: Application = Application(ApplicationSettings(data=json_data), map_data)

if __name__ == "__main__":
    logger.info("Starting Application")
    application.start()
