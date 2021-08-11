from termcolor import colored

COLOR_INFO = "yellow"
COLOR_ERROR = "red"
COLOR_INPUT = "blue"
COLOR_SUCCESS = "green"

def get_choice(input_text: str, no_text: str = None) -> bool:
    # raw_input returns the empty string for "enter"
    choice = input(colored(input_text+" [yes/no]", COLOR_INPUT))
    choice = choice.lower()

    while True:
        if choice in ['yes', 'y', 'ye', '']:
            return True
        elif choice in ['no', 'n']:
            print(colored(no_text, COLOR_ERROR))
            return False
        else:
            print("Please respond with 'yes' or 'no'")