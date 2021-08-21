# Import
import geopy
import geopy.distance
import json
import pandas as pd
import random
import urllib
from datetime import timedelta
from pyroutelib3 import Router
from shapely.geometry import Polygon, Point
from tqdm import tqdm

from data.config import *

global ROUTER, GEOLOCATOR, MANUFACTURER_ID


# -------------------------- Init functions

def init():
    """
    Init router, geolocator, and manufacturers list
    :return:
    """

    def init_manufacturers():
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
        logging.info("Successfully initiated MANUFACTURER_ID dict")
        logging.debug("MANUFACTURER_ID dict: {d}".format(d=MANUFACTURER_ID))

    global ROUTER, GEOLOCATOR
    ROUTER = Router("car")
    GEOLOCATOR = geopy.Nominatim(user_agent=OSM_AGENT)
    init_manufacturers()


# ---

def get_distance(coord_a, coord_b):
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


def get_manufacturerid():
    """
    Get manufacturer id from MANUFACTURER_ID list
    :return: id
    """
    return MANUFACTURER_ID["manufacturer_" + str(random.randint(0, N_MANUFACTURERS - 1))]


def get_nodes(coord_a, coord_b):
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
        logging.info("Successfully computed start and end node")
        return node_a, node_b
    except:
        logging.warning("Failed to compute start and end node")


def get_route(start_node, end_node):
    """
    Finds route between start_node and end_node and converts them to latlon coordinates
    :param start_node: OSM node id
    :param end_node: OSM node id
    :return: list of lat,lon coordinates
    """
    # Get route
    logging.debug("Exec get_route()")
    status, route = ROUTER.doRoute(start_node, end_node)

    if status == 'success':
        # Get route coordinates
        coordinates = list(map(ROUTER.nodeLatLon, route))
        logging.info("Successfully computed route")
        logging.debug("Route: {r}".format(r=coordinates))
        return coordinates
    else:
        logging.warning("Failed to compute route")
        return None


def get_zipcode(lat, lon):
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


def get_random_id(car: bool):
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


def get_random_time():
    """
    This function will return a random datetime between two datetime
    objects.
    :return:
    """
    logging.debug("Exec get_random_time()")
    start = TIME_RANGE[0]
    end = TIME_RANGE[1]

    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    random_time = start + timedelta(seconds=random_second)

    logging.info("Successfully computed random time: {t}".format(t=random_time))

    return random_time


# ------------------------------------------ Functions -------------------------------------------- #

def get_city_boundaries(city, country):
    """

    :param city:
    :param country:
    :return:
    """

    def get_boundary_lonlat(city, country):
        """

        :param city:
        :param country:
        :return:
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
                logging.debug("Found boundary coordinates for {city}, {country}:".format(city=city, country=country))
                logging.debug(i)
                break
        if lonlat == None:
            logging.error(
                "Could not find boundary coordinates for {city}, {country}.".format(city=city, country=country))

        return lonlat

    logging.debug("Exec get_city_boundaries()")

    # for city in cities:
    # Init data dict
    data = {'city': city, 'country': country}
    city = city.replace('ä', 'a').replace('ö', 'o').replace('ü', 'u')

    # Extract coordinates, apply buffer and convert to Polygon
    lonlat = get_boundary_lonlat(city, country)
    poly = Polygon(lonlat).buffer(0.005)
    logging.info("Successfully got polygon for {city}, {country}".format(city=city, country=country))

    return poly


def get_valid_coord(poly):
    """

    :param poly:
    :return:
    """
    logging.debug("Exec get_valid_coord()")
    lon, lat = poly.exterior.xy
    point_validity = False

    while point_validity is False:
        random_lon = round(random.uniform(min(lon), max(lon)), 14)
        random_lat = round(random.uniform(min(lat), max(lat)), 14)
        point_validity = poly.contains(Point(random_lon, random_lat))
        logging.debug("Point validity: {v}".format(v=point_validity))

    return (random_lat, random_lon)


def get_random_coords(poly):
    """

    :param poly:
    :return:
    """
    logging.debug("Exec get_random_coords()")
    dist = 0
    while (dist < MIN_DIST) or (dist > MAX_DIST):
        start_latlon = get_valid_coord(poly)
        end_latlon = get_valid_coord(poly)
        dist = get_distance(start_latlon, end_latlon)
        logging.debug("Distance: {d}".format(d=dist))

    logging.info("Found two random coordinates with distance {d}km".format(d=dist))
    return start_latlon, end_latlon


def compute_trip(start_coord, end_coord):
    logging.debug("Exec compute_trip()")
    try:
        # Find Nodes
        start, end = get_nodes(start_coord, end_coord)

        route_coords = get_route(start, end)

        if route_coords is None:
            logging.ERROR("Route_coords is None")
            return None

        vehicle_ID = get_random_id(True)
        manufacturer_ID = get_manufacturerid()
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
                    logging.info("Could not get ZIP code. Using i-1 ZIP code.")
                    zipcode = trip[i - 1]["zipcode"]
                else:
                    logging.ERROR("Could not get ZIP code! {e}".format(e=e))
                    break

            if i == 0:
                dist = 0
                speed = 0
                seconds = 0
                co2 = 0
            else:
                a = route_coords[i - 1]
                b = route_coords[i]

                # Compute random speed that is between 80% and 115% of SPEED
                dist = get_distance(a, b)
                speed = round(SPEED * random.randint(50, 115) / 100, 0)
                seconds = round((dist / speed) * 60 * 60, 0)
                co2 = round(CO2 * random.randint(70, 130) / 100, 0)

            # Add to totals
            total_dist += round(dist, 2)
            total_seconds += seconds
            timestamp += timedelta(seconds=seconds)
            total_co2 += round(co2, 0)
            logging.debug(
                "Speed: {s}km/h, distance: {d}km, time: {t}s | Total time: {tt}s, Total dist: {td}km".format(s=speed,
                                                                                                             d=dist,
                                                                                                             t=seconds,
                                                                                                             tt=total_seconds,
                                                                                                             td=round(
                                                                                                                 total_dist,
                                                                                                                 2)))

            point = {
                "count": i,
                "vid": vehicle_ID,
                "mid": manufacturer_ID,
                "zipcode": zipcode,
                "timestamp": timestamp,
                "latlon": route_coords[i],
                "dist": dist,
                "seconds": seconds,
                "co2": co2 * dist,
                "total_dist": total_dist,
                "total_seconds": total_seconds,
                "total_co2": total_co2,
                "timestamp_tripstart": timestamp_start,
                "avg_speed": total_dist / ((total_seconds / 60) / 60) if total_seconds > 0 else 0,
                "avg_co2perkm": total_co2 / total_dist if total_dist > 0 else 0
            }
            trip.append(point)

        print(trip[-1])
        df = pd.DataFrame(trip)

        return df

    except Exception as e:
        logging.error("compute_route() failed. {e}".format(e=e))
        return None
