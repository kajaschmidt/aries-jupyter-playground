from functions import *
from datetime import datetime
from termcolor import colored


def main():
    logging.info("-----------------------------------------------------------------------------")
    logging.info("--- INIT ---")
    init()

    df = pd.DataFrame()

    # Get city polygon and find random coordinates within it
    city_poly = get_city_boundaries(CITY, COUNTRY)

    # Iterate through number of journeys and compute them
    for i in range(N_JOURNEYS):

        logging.info("\n--- COMPUTING JOURNEY {i}/{n} ---".format(i=i + 1, n=N_JOURNEYS))

        # Get random start and end coortinates and compute trip
        start_coord, end_coord = get_random_coords(city_poly)
        df_trip = compute_trip(start_coord, end_coord)

        # Add trip index
        df_trip["trip_id"] = i

        if df_trip is None:
            continue

        try:
            df = pd.concat([df, df_trip])
            logging.info(colored("Successfully appended df_trip to df.", "green"))

        except Exception as e:
            logging.info(colored("Failed to append df_trip to df!\nError Message: {e}".format(e=e), "red"))
            df = df_trip

    logging.info("\n--- FINISHED COMPUTING JOURNEYS ---")
    # Save final dataset
    df.to_csv(PATH + FILE_NAME)
    logging.info("\nSaved df as one csv")

    # Split dataset into N_MANUFACTURER parts and save in given directory
    for i, manufacturer_id in enumerate(df.mid.unique()):
        directory = "/manufacturer{i}/".format(i=i)
        df_i = df[df.mid == manufacturer_id]
        df_i.to_csv(PATH + directory + FILE_NAME)
        logging.info(colored(" > Saved data for manufacturer{i}".format(i=i), "green"))

    logging.info("-----------------------------------------------------------------------------")


if __name__ == "__main__":
    main()
