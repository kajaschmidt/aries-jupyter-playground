import asyncio
from termcolor import colored
from typing import Optional

from .helpers import *


class Connection:

    def __init__(self, connection_id, auto_accept: bool = True, auto_ping: bool = True, alias: Optional[str] = None):
        self.connection_id: str = connection_id
        self.is_active: bool = False
        #self.duet_connection_ids: [str] = []
        self.presentation_exchange_ids: [str] = []
        self.verified_attributes: list = []
        self.self_attested_attributes: list = []
        self.alias: Optional[str] = alias
        self.auto_ping: bool = auto_ping
        self.auto_accept: bool = auto_accept
        self.connection_with: Optional[str] = None

        self.is_duet_connection: bool = False
        self.duet_token_partner: Union[Optional[asyncio.Future()], Optional[str]] = None
        self.duet_token: Optional[str] = None

        # self.display()

    def display(self, duet: bool = False) -> None:
        """
        Display Connection with its attributes
        Returns: -

        """
        is_active_color = COLOR_SUCCESS if self.is_active is True else COLOR_ERROR

        print("\n---------------------------------------------------------------------")
        print(colored("Connection with {i}".format(i=self.connection_with), attrs=["bold"]))
        print("Connection ID : ", self.connection_id)
        print("Connection with : ", self.connection_with)
        if duet is False:
            print("Is Active : ", colored(self.is_active, is_active_color))
            print("Auto Ping : ", self.auto_ping)
            print("Auto Accept : ", self.auto_accept)
            print("Connection Alias : ", self.alias)
            print("Presentation Exchange IDs : ", self.presentation_exchange_ids)
        else:
            print("Is Duet Connection : ", self.is_duet_connection)
            print("Duet Token : ", self.duet_token)
            print("Partner's Duet Token : ", self.duet_token_partner)
        print("---------------------------------------------------------------------")