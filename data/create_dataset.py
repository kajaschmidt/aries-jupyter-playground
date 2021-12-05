from functions import *


def main() -> None:
    """
    Execute the main logic to create a synthetic dataset of trip data in config.CITY, config.COUNTRY.
    Saves dataset in data/, and splits the data into N_MANUFACTURERS and stores the individual datasets under
    data/<manufacturer>/dataset/
    Returns: -

    """

    logging.info("-----------------------------------------------------------------------------")

    logging.info("--- INIT ---")
    init()
    df = pd.DataFrame()

    # Get geo_data polygon and find random coordinates within it
    city_poly = get_city_boundaries()

    # Iterate through number of journeys and compute them
    for i in range(N_JOURNEYS):

        logging.info("--- COMPUTING JOURNEY {i}/{n} ---".format(i=i + 1, n=N_JOURNEYS))

        # Get random start and end coordinates and compute trip
        start_coord, end_coord = get_random_coords(city_poly)
        df_trip = compute_trip(start_coord, end_coord)

        if df_trip is None:
            continue

        try:
            df_trip["trip_id"] = i
            df = pd.concat([df, df_trip])
            logging.info(colored("Successfully appended df_trip to df.", "green"))

        except Exception as e:
            logging.info(colored("Failed to append df_trip to df!\nError Message: {e}".format(e=e), "red"))
            df = df_trip

        if DEBUG is False:
            logging.info("...waiting {n} seconds until next run...".format(n=PAUSE))
            time.sleep(PAUSE)

    logging.info("--- FINISHED COMPUTING JOURNEYS ---")

    # Save final dataset and save fractions of dataset per manufacturer
    save_df(df)
    logging.info("-----------------------------------------------------------------------------")


if __name__ == "__main__":
    main()
