import os
from datetime import datetime as dt
import logging

logging.basicConfig(level=logging.INFO)

# Setup variables
OSM_AGENT = 'thesis-fake-dataset'
PATH = os.path.dirname(os.path.realpath(__file__))
FILE_NAME = "dataset_{time}.csv".format(time=dt.now())

# Execution variables -- can be modified
N_JOURNEYS = 2  # Number of journeys computed
N_MANUFACTURERS = 2  # Number of manufacturers for whom journeys will be computed
CITY = "Berlin"
COUNTRY = "DE"
TIME_RANGE = [dt.strptime('2021-08-19 00:00:00', '%Y-%m-%d %H:%M:%S'),
              dt.strptime('2021-08-20 00:00:00', '%Y-%m-%d %H:%M:%S')]
KM_PER_HOUR = 50  # Default speed (km/h)
CO2_PER_KM = 130  # Default CO2 emmission (g/km)
MIN_DIST_KM = 2
MAX_DIST_KM = 7
