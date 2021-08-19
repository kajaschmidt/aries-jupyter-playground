from termcolor import colored

COLOR_INFO = "blue"
COLOR_ERROR = "red"
COLOR_INPUT = "magenta"
COLOR_SUCCESS = "green"


def get_choice(input_text: str, no_text: str = None) -> bool:
    """
    Get a choice from the user. Prompt three times if they choose "no" or none of the options.

    Args:
        input_text: Input text that is prompted
        no_text: Text displayed when "no" is selected

    Returns: Decision whether to accept the choice (True) or not (False)

    """
    # Iterate three times to prompt user
    for i in range(3):
        # raw_input returns the empty string for "enter"
        choice = input(colored(input_text+" [yes/no]", COLOR_INPUT))
        choice = choice.lower()

        if choice in ['yes', 'y', 'ye', '']:
            return True
        elif choice in ['no', 'n']:
            print(colored(no_text, COLOR_ERROR))
            return False
        else:
            print("Please respond with 'yes' or 'no'")

    # Return false if prompted over three times
    return False