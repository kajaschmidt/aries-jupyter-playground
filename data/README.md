# Create artificial car trip datasets

Artificial trip data of the individual manufacturers is created to demonstrate the use case without revealing any actual information of any car manufacturer. 

### Overview
* `create_dataset.py`: Main file to create an artificial dataset. Splits the dataset into `N_MANUFACTURERS` and stores them in the respective manufacturers' directory (see `config.py` file for specifications)
* `config.py`: Specifies number of manufacturers, journeys, city, time range, average km/h etc. to create the artificial dataset
* `functions.py`: helper functions for `create_dataset.py`
* `requirements.txt`: packages required to create the artificial dataset

The final datasets contain the following structure (stored as a flattened CSV file):

```
trip_coordinate = {
    "trip_id": 0, # id of trip
    "i": 0, # ith coordinate of the trip
    "vehicle_id": "V74896255", # unique vehicle id (constant during one trip)
    "manufacturer_id": "V00274", # random manufacturer id (there are N_MANUFACTURERS ids in total)
    "latlon": (52.5903807, 13.5387713), # coordinate of route
    "timestamp": "2021-08-19 11:38:58", # randomly generated timestamp if start_coordinate. Else: extrapolated using random speed
    "dist": 0.09, # km between latlon and latlon of i-1
    "seconds": 4, # time between timestamp and timestamp of i-1
    "co2_grams": 4.65, # co2 grams emitted since i-1
}
```

### Run
Run `create_dataset.py` file to try out yourself. If `DEBUG = False` in `config.py` file, the script will pause 60 seconds between every route's computation to ensure there is no timeout from `pyroutelib3`.
It is advisable to try `DEBUG = True` and `N_JOURNEYS = 10` (or any smaller number) at first.