from datetime import datetime as dt
import logging
logging.basicConfig(level=logging.INFO)

# Variables
N_JOURNEYS = 1000
N_MANUFACTURERS = 3
CITY = "Berlin"
COUNTRY = "DE"
OSM_AGENT = 'thesis-fake-dataset'
TIME_RANGE = [dt.strptime('2021-07-11 00:00:00', '%Y-%m-%d %H:%M:%S'),
              dt.strptime('2021-07-19 00:00:00', '%Y-%m-%d %H:%M:%S')]
SPEED = 50
CO2 = 130
MIN_DIST = 2
MAX_DIST = 7