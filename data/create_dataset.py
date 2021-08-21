from data.functions import *


def main():
    logging.info("--- INIT ---")
    init()
    df = pd.DataFrame()

    # Get city polygon and find random coordinates within it
    city_poly = get_city_boundaries(CITY, COUNTRY)

    for i in range(N_JOURNEYS):

        logging.info("--- COMPUTING JOURNEY {i}/{n} ---".format(i=i + 1, n=N_JOURNEYS))
        start_coord, end_coord = get_random_coords(city_poly)
        df_trip = compute_trip(start_coord, end_coord)

        if df_trip is None:
            continue

        try:
            df = pd.concat([df, df_trip])
            logging.info("Successfully appended df_trip to df.")

        except Exception as e:
            logging.info("Failed to append df_trip to df!\nError Message: {e}".format(e=e))
            df = df_trip

    df.to_csv("dataset.csv")
    logging.info("Saved df as csv")


if __name__ == "__main__":
    main()
