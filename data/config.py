import os
from datetime import datetime as dt
import logging

logging.basicConfig(level=logging.INFO)

# Setup variables
DEBUG = False  # If False, run with a time.sleep(5) to prevent bandwidth limit error
PAUSE = 60  # Seconds of pause if DEBUG == False
OSM_AGENT = 'thesis-fake-dataset'
PATH = os.path.dirname(os.path.realpath(__file__))+"/"
FILE_NAME = "testdata_{time}.csv".format(time=dt.now()) if DEBUG is True else "data.csv"

# Execution variables -- can be modified
N_JOURNEYS = 1000  # Number of journeys computed
N_MANUFACTURERS = 3  # Number of manufacturers for whom journeys will be computed
CITY = "Berlin"
COUNTRY = "DE"
TIME_RANGE = [dt.strptime('2021-08-19 00:00:00', '%Y-%m-%d %H:%M:%S'),
              dt.strptime('2021-08-20 00:00:00', '%Y-%m-%d %H:%M:%S')]

KM_PER_HOUR = 50  # Default speed (km/h)
CO2_PER_KM = 130  # Default CO2 emmission (g/km)
MIN_DIST_KM = 2
MAX_DIST_KM = 7
