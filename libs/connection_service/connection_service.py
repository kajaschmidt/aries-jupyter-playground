# stdlib
import asyncio
import ast
import logging
from typing import Dict as TypeDict
from typing import List as TypeList
from typing import Optional
from .connection import Connection
import qrcode
import time
from pprintpp import pprint
from termcolor import colored
from .helpers import *

# third party
from aries_cloudcontroller import AriesAgentController
import nest_asyncio

nest_asyncio.apply()

class ConnectionService:
    def __init__(
            self,
            agent_controller: AriesAgentController,
    ) -> None:
        self.agent_controller = agent_controller
        self.agent_listeners = [
            {"topic": "connections", "handler": self._connections_handler},
            {"topic": "prover_proof", "handler": self._prover_proof_handler},
            {"topic": "verifier_proof", "handler": self._verifier_proof_handler},
            {"topic": "issue_credential", "handler": self._issuer_handler},
            {"topic": "basicmessages", "handler": self._messages_handler},
        ]
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        self.connections: [Connection] = []

        listener_topics = [s["topic"] for s in self.agent_listeners]

        print(colored("Initiate ConnectionService:", attrs=["bold"]))
        print("* Defines and registers agent listeners: ", listener_topics)
        print("* Stores initiated connections")
        print("* Allows to easily create and accept connection invitations")
        print("* Facilitates process of issuing and verifying verifiable credentials")

    def get_connection(self, connection_id: str):
        """
        Get connection by connection_id
        Returns: Connection (if it exists) or None
        """
        for connection in self.connections:
            if connection.connection_id == connection_id:
                return connection
        return None

    def get_connections(self):
        """
        Returns: All connections of self
        """
        return self.connections

    def create_connection_invitation(self, alias, auto_accept: str, public: str, multi_use: str) -> str:
        """
        Creates invitation by agent_controller, and prints the invitation that must be forwarded to an external agent
        Args:
            alias: Alias name for invited connection
            auto_accept: auto-accept the responses sent by the external agent
            public: Use public DID
            multi_use: Use invitation for multiple invitees

        Returns: - (prints invitation)

        """
        # Loop until connection is created
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.create_invitation(alias, auto_accept, public, multi_use)
        )

        # Get connection_id and store as new connection in self
        connection_id = invitation_response["connection_id"]
        new_connection = Connection(connection_id)
        self.connections.append(new_connection)

        # Print invitation to share it with an external agent
        invitation = invitation_response["invitation"]
        print(colored("\nCopy & paste invitation and share with external agent:", COLOR_INPUT, attrs=["bold"]))
        pprint(invitation)
        print("\n")

        if auto_accept == "true":
            state = None
            while state != "response":
                loop = asyncio.get_event_loop()
                state_of_invite = loop.run_until_complete(self.agent_controller.connections.get_connection(connection_id))
                state = state_of_invite["state"]
                time.sleep(3) # Add time buffer to limit requests

        else:
            state = None
            while state != "request":
                loop = asyncio.get_event_loop()
                state_of_invite = loop.run_until_complete(self.agent_controller.connections.get_connection(connection_id))
                state = state_of_invite["state"]
                time.sleep(3) # Add time buffer to limit requests

            choice = get_choice("Accept invitation request response by external agent?", "Please execute agent_controller._accept_connection_invitation() to proceed")
            if choice is True:
                self._accept_invitation_response(connection_id)

        self._trust_ping(connection_id)
        return connection_id

    def wrapper_receive_connection_invitation(self, alias, auto_accept, label=None):
        invitation = input(colored("Please enter invitation received by external agent: ", "blue"))
        invitation = ast.literal_eval(invitation)

        response = self._receive_connection_invitation(invitation, alias, auto_accept, label)
        return response

    def _receive_connection_invitation(self, invitation: dict, alias, auto_accept, label=None):
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.receive_invitation(invitation, alias, auto_accept)
        )

        # Get connection_id and store as a new connection in self
        connection_id = invitation_response["connection_id"]
        new_connection = Connection(connection_id)
        self.connections.append(new_connection)

        # Stop if auto_accept was set to true
        if auto_accept == "true":
            return connection_id

        # raw_input returns the empty string for "enter"
        choice = get_choice("Accept invitation {c}?".format(c=connection_id), no_text="Please execute agent_controller._accept_connection_invitation() to proceed")
        if choice is True:
            self._accept_connection_invitation(connection_id, label)

        return connection_id

    def _accept_connection_invitation(self, connection_id, label, endpoint=None):
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        accept_response = loop.run_until_complete(
            self.agent_controller.connections.accept_invitation(connection_id, label, endpoint)
        )

    def _accept_invitation_response(self, connection_id: str) -> str:

        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        request_response = loop.run_until_complete(
            self.agent_controller.connections.accept_request(connection_id)
        )

    def _trust_ping(self, connection_id):
        # @TODO: see if there is some other auto_attribute that needs to be taken into consideration!
        # raw_input returns the empty string for "enter"
        choice = get_choice("Send trust ping to finalize connection?",
                            no_text="Please execute agent_controller._trust_ping() to proceed")
        if choice is True:
            # Loop until connection invitation is received
            loop = asyncio.get_event_loop()
            ping_response = loop.run_until_complete(
                self.agent_controller.messaging.trust_ping(connection_id, "send trust ping")
            )

    def send_message(self, connection_id, basic_message):
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        message_response = loop.run_until_complete(
            self.agent_controller.messaging.send_message(connection_id, basic_message)
        )
        print("supposedly sent message", message_response)

    def offer_vc(self, connection_id, schema_id, cred_def_id, credential_attributes=None, comment=None, auto_remove=True, trace=False):
        """
        Gets schema ID and let's issuer fill out the attributes, to then offer a VC to the external
        agent
        Args:
            connection_id: ID of the connection to whom a VC should be offered to
            schema_id: ID of the scheme
            cred_def_id: id that authorizes agent to issue a credential for that scheme
            credential_attributes: list of {"name": <name>, "value": <value>} dicts with vc information
            comment: comment
            auto_remove: remove credential record after it has been issued
            trace: trace ACA-PY instance
        Returns:
        """
        loop = asyncio.get_event_loop()
        schema_info = loop.run_until_complete(
            self.agent_controller.schema.get_by_id(schema_id)
        )

        if credential_attributes is None:
            attributes = schema_info["attrNames"]
            credential_attributes = []
            print(colored("Please enter the following information for the {n} scheme (ID: {id}): ".format(n=schema_info['name'], id=schema_id), COLOR_INPUT, attrs=["bold"]))
            for attr in attributes:
                value = input(colored("{n}: ".format(n=attr), COLOR_INPUT))
                credential_attributes.append({"name": attr, "value": value})
            pprint(credential_attributes)

        loop = asyncio.get_event_loop()
        message_response = loop.run_until_complete(
            self.agent_controller.issuer.send_credential(connection_id, schema_id, cred_def_id, credential_attributes, comment, auto_remove, trace)
        )

        print("message response:", message_response)
        return message_response

    def request_vc(self, connection_id, state):
        print("this is where you can request a vc")



    # Connection handlers
    def _connections_handler(self, payload):

        state = payload['state']
        connection_id = payload["connection_id"]
        their_role = payload["their_role"]
        routing_state = payload["routing_state"]
        rfc_state = payload["rfc23_state"]

        print("\n---------------------------------------------------------------------")
        print(colored("Connection Webhook Event Received", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("State : ", colored("{s} ({r})".format(s=state, r=rfc_state), COLOR_INFO))
        print("Routing State : {routing}".format(routing=routing_state))
        if 'their_label' in payload:
            print(f"Connection with : ", payload['their_label'])
        print("Their Role : ", their_role)
        print("---------------------------------------------------------------------")

        if state == "active":
            print(colored("Connection ID: {0} is now active.".format(connection_id), COLOR_SUCCESS, attrs=["bold"]))

    def _issuer_handler(self, payload):
        connection_id = payload['connection_id']
        exchange_id = payload['credential_exchange_id']
        state = payload['state']
        role = payload['role']

        print("\n---------------------------------------------------------------------")
        print(colored("Handle Issue Credential Webhook", attrs=["bold"]))
        print(f"Connection ID : {connection_id}")
        print(f"Credential exchange ID : {exchange_id}")
        print("Agent Protocol Role : ", role)
        print("Protocol State : ", colored(state, COLOR_INFO))
        print("---------------------------------------------------------------------")

        if state == "offer_sent":
            proposal = payload["credential_proposal_dict"]
            attributes = proposal['credential_proposal']['attributes']
            print(f"Offering : \n {attributes}")
            ## YOUR LOGIC HERE
        elif state == "request_received":
            print("Request for credential received")
            ## YOUR LOGIC HERE
        elif state == "credential_sent":
            print("Credential Sent")
            ## YOUR LOGIC HERE

    def _messages_handler(sefl, payload):
        connection_id = payload["connection_id"]
        print("\n---------------------------------------------------------------------")
        print("Handle message", connection_id)
        pprint(payload)
        print("---------------------------------------------------------------------")

    def _prover_proof_handler(self, payload):
        """

        Args:
            payload:

        Returns:

        """
        role = payload["role"]
        connection_id = payload["connection_id"]
        pres_ex_id = payload["presentation_exchange_id"]
        state = payload["state"]
        print("\n---------------------------------------------------------------------")
        print(colored("Handle present-proof", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("Presentation Exchange ID : ", pres_ex_id)
        print("Protocol State : ", state)
        print("Agent Role : ", role)
        print("Initiator : ", payload["initiator"])
        print("---------------------------------------------------------------------")

        if state == "request_received":
            presentation_request = payload["presentation_request"]
            print("Recieved Presentation Request\n")
            print("\nRequested Attributes - Note the restrictions. These limit the credentials we could respond with\n")
            print(presentation_request["requested_attributes"])
        elif state == "presentation_sent":
            print("Presentation sent\n")

        elif state == "presentation_acked":
            print("Presentation has been acknowledged by the Issuer")

    def _verifier_proof_handler(self, payload):
        """

        Args:
            payload:

        Returns:

        """
        role = payload["role"]
        connection_id = payload["connection_id"]
        pres_ex_id = payload["presentation_exchange_id"]
        state = payload["state"]
        print("\n---------------------------------------------------------------------")
        print(colored("Handle present-proof", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("Presentation Exchange ID : ", pres_ex_id)
        print("Protocol State : ", state)
        print("Agent Role : ", role)
        print("Initiator : ", payload["initiator"])
        print("---------------------------------------------------------------------")

        if state == "request_sent":
            print("Presentation Request\n")
            print(payload["presentation_request"])
            print("\nThe presentation request is encoded in base64 and packaged into a DIDComm Message\n")
            print(payload["presentation_request_dict"])
            print("\nNote the type defines the protocol present-proof and the message request-presentation\n")
            print(payload["presentation_request_dict"]["@type"])
        elif state == "presentation_received":
            print("Presentation Received")
            # print("We will not go into detail on this payload as it is comparable to the presentation_sent we looked at in the earlier cell.")
            print("This is the full payload\n")
            print(payload)
        else:
            print("Paload \n")
            print(payload)
