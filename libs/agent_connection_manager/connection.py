import asyncio
from termcolor import colored
from typing import Optional

from .helpers import *


class Connection:

    def __init__(self, connection_id, auto_accept: bool = True, auto_ping: bool = True, alias: Optional[str] = None):
        self.connection_id = connection_id
        self.is_active = False
        self.duet_connection_ids: [str] = []
        self.presentation_exchange_ids: [str] = []
        self.verified_attributes = []
        self.self_attested_attributes = []
        self.alias = alias
        self.auto_ping = auto_ping
        self.auto_accept = auto_accept
        self.connection_with = None

        # self.display()

    def display(self) -> None:
        """
        Display Connection with its attributes
        Returns: -

        """
        is_active_color = COLOR_SUCCESS if self.is_active is True else COLOR_ERROR

        print("\n---------------------------------------------------------------------")
        print(colored("Connection with {i}".format(i=self.connection_with), attrs=["bold"]))
        print("Connection ID : ", self.connection_id)
        print("Connection with : ", self.connection_with)
        print("Is Active : ", colored(self.is_active, is_active_color))
        # print("Auto Ping : ", self.auto_ping)
        # print("Auto Accept : ", self.auto_accept)
        print("Connection Alias : ", self.alias)
        print("Presentation Exchange IDs : ", self.presentation_exchange_ids)
        print("---------------------------------------------------------------------")
