# Import
import datetime
import json
import random
import time
import urllib
from datetime import timedelta
from typing import Optional

import geopy
import geopy.distance
import pandas as pd
from pyroutelib3 import Router
from shapely.geometry import Polygon, Point
from termcolor import colored
from tqdm import tqdm

from config import *

global ROUTER, GEOLOCATOR, MANUFACTURER_ID


# -------------------------- Init functions

def init() -> None:
    """
    Init router, geolocator, and manufacturers list
    :return:
    """

    def init_manufacturers() -> None:
        """
        Init List with IDs of manufacturers
        :return:
        """
        global MANUFACTURER_ID

        logging.debug("Exec init_manufacturers()")
        entries = dict()
        for i in range(N_MANUFACTURERS):
            manufacturer = "manufacturer_{i}".format(i=str(i))
            entries[manufacturer] = get_random_id(False)

        MANUFACTURER_ID = entries
        logging.info(colored("Successfully initiated MANUFACTURER_ID dict", "green"))
        logging.debug("MANUFACTURER_ID dict: {d}".format(d=MANUFACTURER_ID))

    global ROUTER, GEOLOCATOR
    ROUTER = Router("car")
    GEOLOCATOR = geopy.Nominatim(user_agent=OSM_AGENT)
    init_manufacturers()


# ---

def get_distance(coord_a: tuple, coord_b: tuple) -> float:
    """
    Compute distance in km between start_coord and end_coord
    :param coord_a: (lat, lon)
    :param coord_b: (lat, lon)
    :return: float (km, rounded to 2 decimal places)
    """
    logging.debug("Exec get_distance()")
    dist = round(geopy.distance.distance(coord_a, coord_b).km, 2)
    logging.debug("Distance between points: {d}km".format(d=dist))
    return dist


def get_manufacturerid() -> str:
    """
    Get manufacturer id from MANUFACTURER_ID list
    :return: id
    """
    return MANUFACTURER_ID["manufacturer_" + str(random.randint(0, N_MANUFACTURERS - 1))]


def get_nodes(coord_a: tuple, coord_b: tuple) -> tuple:
    """
    Get start and end nodes from route
    :param coord_a: (lat, lon)
    :param coord_b: (lat, lon)
    :return: node_a ID (from OSM), node_b ID (from OSM)
    """
    logging.debug("Exec get_nodes()")
    try:
        node_a = ROUTER.findNode(coord_a[0], coord_a[1])
        node_b = ROUTER.findNode(coord_b[0], coord_b[1])
        logging.info(colored("Successfully computed start and end node", "green"))
        return node_a, node_b
    except:
        logging.warning(colored("Failed to compute start and end node", "red"))


def get_route(start_node: str, end_node: str) -> Optional[list]:
    """
    Finds route between start_node and end_node and converts them to latlon coordinates
    :param start_node: OSM node id
    :param end_node: OSM node id
    :return: list of lat,lon coordinates
    """
    # Get route
    logging.debug("Exec get_route()")

    try:
        status, route = ROUTER.doRoute(start_node, end_node)
        # Get route coordinates
        coordinates = list(map(ROUTER.nodeLatLon, route))
        logging.info(colored("Successfully computed route", "green"))
        logging.debug("Route: {r}".format(r=coordinates))
        return coordinates
    except:
        logging.warning(colored("Failed to get a route", "red"))
        return None


def get_zipcode(lat: float, lon: float) -> str:
    """
    Get ZIP code from lat and lon
    :param lat: latitude
    :param lon: longitude
    :return: zip code
    """
    logging.debug("Exec get_zipcode()")
    location = GEOLOCATOR.reverse((lat, lon))
    zip_code = location.raw['address']['postcode']

    return zip_code


def get_random_id(car: bool) -> str:
    """
    Generate random ID for vehicle or manufacturer
    :param car: (bool) if True: get V-number, else get M-number
    :return: random_id (str)
    """
    logging.debug("Exec get_random_id()")
    if car is True:
        random_id = 'V{0:0{x}d}'.format(random.randint(0, 10 ** 8), x=8)
    else:
        random_id = 'V{0:0{x}d}'.format(random.randint(0, 10 ** 5), x=5)
    logging.info("Random id: {}".format(random_id))
    return random_id


def get_random_time() -> datetime.datetime:
    """
    This function will return a random datetime between two datetime
    objects.
    :return: datetime
    """
    logging.debug("Exec get_random_time()")
    start = TIME_RANGE[0]
    end = TIME_RANGE[1]

    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    random_time = start + timedelta(seconds=random_second)

    logging.info(colored("Successfully computed random time: {t}".format(t=random_time), "green"))

    return random_time


# ------------------------------------------ Functions -------------------------------------------- #

def get_city_boundaries() -> Polygon:
    """
    Get geo_data boundaries of the geo_data specified in config
    Returns: polygon with geo_data boundaries

    """

    def get_boundary_lonlat(city: str, country: str) -> Optional[list]:
        """
        Get the city boundaries of city in country to use as guidelines which lonlat are valid or not.
        :param city: string with city name
        :param country: string with country name
        :return: list with lonlat or None
        """

        logging.debug("Exec nested function get_boundary_lonlat()")

        url = "https://nominatim.openstreetmap.org/search.php?q=" + city + "+" + country + "&polygon_geojson=1&format=json"
        page = urllib.request.urlopen(url).read()
        osm_data = json.loads(page)
        lonlat = None
        for i in osm_data:
            if (i['osm_type'] == 'relation') & (i['class'] == 'boundary'):
                lonlat = i['geojson']['coordinates']
                while len(lonlat) < 10:
                    lonlat = lonlat[0]
                logging.debug(
                    colored("Found boundary coordinates for {city}, {country}:".format(city=city, country=country),
                            "green"))
                logging.debug(i)
                break
        if lonlat == None:
            logging.error(colored(
                "Could not find boundary coordinates for {city}, {country}.".format(city=city, country=country), "red"))

        return lonlat

    logging.debug("Exec get_city_boundaries()")

    # Extract coordinates, apply buffer and convert to Polygon for the geo_data
    city = CITY.replace('ä', 'a').replace('ö', 'o').replace('ü', 'u')
    lonlat = get_boundary_lonlat(city, COUNTRY)
    poly = Polygon(lonlat).buffer(0.005)
    logging.info(colored("Successfully got polygon for {city}, {country}".format(city=CITY, country=COUNTRY), "green"))

    return poly


def get_valid_coord(poly: Polygon) -> tuple:
    """
    Get random coordinate within the boundaries of a city
    :param poly: polygon with city boundaries
    :return: (lat, lon)
    """
    logging.debug("Exec get_valid_coord()")
    lon, lat = poly.exterior.xy
    point_validity = False

    while point_validity is False:
        random_lon = round(random.uniform(min(lon), max(lon)), 14)
        random_lat = round(random.uniform(min(lat), max(lat)), 14)
        point_validity = poly.contains(Point(random_lon, random_lat))
        logging.debug("Point validity: {v}".format(v=point_validity))

    latlon = (random_lat, random_lon)

    return latlon


def get_random_coords(poly: Polygon) -> tuple:
    """
    Get random coordinates that are not too far away apart from one another
    :param poly: defined boundaries in which random coordinates are generated
    :return: tuple with start and end latlon
    """
    logging.debug("Exec get_random_coords()")
    dist = 0
    while (dist < MIN_DIST_KM) or (dist > MAX_DIST_KM):
        start_latlon = get_valid_coord(poly)
        end_latlon = get_valid_coord(poly)
        dist = get_distance(start_latlon, end_latlon)
        logging.debug("Distance: {d}".format(d=dist))

    logging.info(colored("Found two random coordinates with distance {d}km".format(d=dist), "green"))
    return start_latlon, end_latlon


def compute_trip(start_coord: tuple, end_coord: tuple) -> Optional[pd.DataFrame]:
    """
    Computes a (realistic) route between start and end coordinate, and enriches the dataset with manufacturer and
    vehicle IDs, speed, co2 value, distance, time.
    Args:
        start_coord: latlon coordinate
        end_coord: latlon coordinate

    Returns: pandas Dataframe with information of a trip between start_coord and end_coord.

    """
    logging.debug("Exec compute_trip()")
    try:
        # Find Nodes
        start, end = get_nodes(start_coord, end_coord)

        route_coords = get_route(start, end)

        if route_coords is None:
            logging.ERROR("Route_coords is None")
            return None

        vehicle_id = get_random_id(True)
        manufacturer_id = get_manufacturerid()
        timestamp_start = get_random_time()
        timestamp = timestamp_start
        total_dist = 0
        total_seconds = 0
        total_co2 = 0

        trip = []

        for i in tqdm(range(len(route_coords))):

            try:
                zipcode = get_zipcode(route_coords[i][0], route_coords[i][1])

            except Exception as e:
                if i > 0:
                    logging.info(colored("Could not get ZIP code. Using i-1 ZIP code.", "yellow"))
                    zipcode = trip[i - 1]["zipcode"]
                else:
                    logging.ERROR(colored("Could not get ZIP code! {e}".format(e=e), "red"))
                    break

            if i == 0:
                # Init variables
                seconds = 0
                dist = 0
                km_per_hour = 0
                co2_per_km = 0
                co2_relative = 0
            else:
                # Else, compute route and random speed, distance, co2 grams, and seconds
                a = route_coords[i - 1]
                b = route_coords[i]

                # Compute random speed that is between 60% and 115% of the previously recorded speed
                dist = get_distance(a, b)
                if dist == 0:
                    km_per_hour = 0
                    co2_per_km = 0
                    co2_relative = 0
                    seconds = random.randint(0, 10)
                else:
                    km_per_hour = round(speed_old * random.randint(60, 115) / 100, 0)
                    co2_per_km = round(co2_per_km_old * random.randint(70, 120) / 100, 0)
                    co2_relative = round(co2_per_km * dist, 2)
                    seconds = round((dist / km_per_hour) * 60 * 60, 0)

            # Store old variables for next round (to make values somewhat cohesive)
            speed_old = km_per_hour if km_per_hour > 0 else KM_PER_HOUR
            co2_per_km_old = co2_per_km if co2_per_km > 0 else CO2_PER_KM

            # Add to totals
            total_dist = round(total_dist + dist, 2)
            total_seconds += seconds
            timestamp += timedelta(seconds=seconds)
            total_co2 = round(total_co2 + co2_relative, 0)
            logging.debug(
                "Speed: {s}km/h, Distance: {d}km, Time: {t}s, CO2: {co}g | Total time: {tt}s, Total dist: {td}km, Total CO2: {tco}g".format(
                    s=km_per_hour,
                    d=dist,
                    co=co2_relative,
                    t=seconds,
                    tt=total_seconds,
                    td=round(
                        total_dist,
                        2),
                    tco=total_co2))

            point = {
                "vehicle_id": vehicle_id,
                "manufacturer_id": manufacturer_id,
                "zipcode": zipcode,
                "timestamp": timestamp,
                "latlon": route_coords[i],
                "dist": dist,
                "seconds": seconds,
                "co2_grams": co2_relative,  # CO2 grams / km relative to travelled distance
                "total_dist": total_dist,
                "total_seconds": total_seconds,
                "total_co2_grams": total_co2,
                "timestamp_tripstart": timestamp_start,
                "avg_kmperhour": total_dist / ((total_seconds / 60) / 60) if total_seconds > 0 else 0,
                "avg_co2perkm": total_co2 / total_dist if total_dist > 0 else 0
            }
            trip.append(point)

            if DEBUG is False:
                time.sleep(1)

        logging.info(colored(trip[-1], "blue"))
        df = pd.DataFrame(trip)

        return df

    except Exception as e:
        logging.error(colored("compute_route() failed. {e}".format(e=e), "red"))
        return None


def save_df(data: pd.DataFrame) -> None:
    """
    Store dataset as a whole (for safekeeping), and split into individual manufacturer datasets
    Args:
        data: pandas dataframe with artificial trip data

    Returns: -

    """
    # Reset index and rename to i (count per trip)
    data = data.reset_index().rename(columns={"index": "i"})

    # Store dataset
    # data.to_csv(PATH + FILE_NAME)
    # logging.info(colored("Saved df as one csv", "green"))

    # Split dataset into N_MANUFACTURER parts and save in given directory
    for i, manufacturer_id in enumerate(data.manufacturer_id.unique()):
        directory = "manufacturer{i}/".format(i=i + 1)
        data_i = data[data.manufacturer_id == manufacturer_id]
        data_i = data_i.reset_index(drop=True)
        dir_exists = os.path.exists(PATH + directory)
        if dir_exists is False:
            os.makedirs(PATH + directory)
        data_i.to_csv(PATH + directory + FILE_NAME)
        logging.info(
            colored(" > Stored data for manufacturer{i} under {p}".format(i=i + 1, p=PATH + directory + FILE_NAME),
                    "green"))
