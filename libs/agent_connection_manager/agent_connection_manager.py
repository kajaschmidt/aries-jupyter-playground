#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Provides managers specific to SSI / Trust Triangle roles.

AgentConnectionManager (ACM) is a superclass that helps to manage aries agents, send messages, and establish aries and
duet connections. The subclasses (RelyingParty, CredentialHolder, IssuingAuthority) have functionalities that are
specific to their roles in the trust triangle (e.g., only IssuingAuthority can issue verifiable credentials).
"""

# Standard libraries and 3rd party packages
import ast
import asyncio
import json
import logging
import nest_asyncio
import qrcode  # @todo: what does this do
import requests
import time
from aries_cloudcontroller import AriesAgentController
from pprintpp import pprint
from syft.grid.duet.exchange_ids import DuetCredentialExchanger
from termcolor import colored
from typing import Dict as TypeDict  # @todo: what does this do
from typing import List as TypeList  # @todo: what does this do
from typing import Optional
from typing import Tuple
from typing import Union

# local sources
from .connection import Connection
from .helpers import *
from .message import Message

nest_asyncio.apply()


# @todo: might have to make this into a duetcredentialexchanger...
class AgentConnectionManager:

    def __init__(self, agent_controller: AriesAgentController) -> None:
        self.agent_controller = agent_controller
        self.agent_listeners = [
            {"topic": "connections", "handler": self._connections_handler},
            {"topic": "basicmessages", "handler": self._messages_handler},
        ]
        self.connections: [Connection] = []
        self.messages: [Message] = []
        self.role = None

    def get_connection(self, connection_id: str) -> Optional[Connection]:
        """
        Get connection by connection_id
        Returns: Connection (if it exists) or None
        """
        for connection in self.connections:
            if connection.connection_id == connection_id:
                return connection
        return None

    def get_connections(self) -> list[Optional[Connection]]:
        """
        Returns: Get all connections of the agent
        """
        return self.connections

    def get_active_connections(self) -> list[Optional[Connection]]:
        """
        Get all connections where Connection.is_active = True
        Returns: list of active connections

        """
        return [c for c in self.connections if c.is_active is True]

    def get_connection_id(self, agent_name: str) -> list[Optional[Connection]]:
        """
        Returns list of connection IDs with a particular agent
        Args:
            agent_name: name of agent with whom the connection is shared

        Returns: list of connection ids shared with agent_name

        """
        connection_ids = [c.connection_id for c in self.connections if c.connection_with == agent_name]
        return connection_ids

    def _store_connection_id(self, connection_id: str, auto_accept: Optional[bool] = None,
                             auto_ping: Optional[bool] = None,
                             alias: Optional[str] = None) -> Connection:
        """
        Verify if connection_id exists already. If yes, return it. Else, add it to self.connections and return it.
        Args:
            connection_id: connection_id
            auto_accept: whether connection is auto_accepted or not
            auto_ping: whether connection should be auto_pinged or not
            alias: whether connection has an alias or not

        Returns: Connection (either new or updated)

        """
        # Get conn. If conn does not yet exist, this will return None
        conn = self.get_connection(connection_id)
        append_conn = False

        # Else create a new conn
        if conn is None:
            conn = Connection(connection_id)
            append_conn = True

        # Update variables of conn
        if auto_accept is not None:
            conn.auto_accept = auto_accept
        if auto_ping is not None:
            conn.auto_ping = auto_ping
        if alias is not None:
            conn.alias = alias

        # Append connection to self.connections if it is newly created
        if append_conn is True:
            self.connections.append(conn)

        return conn

    def get_message(self, message_id: Optional[str] = None) -> Optional[Message]:
        """
        Get connection by connection_id
        Returns: Print of message
        """
        # Get message ID if it was not provided
        if message_id is None:
            print(colored("Please enter Message ID :", COLOR_INPUT, attrs=["bold"]),
                  colored("(Check agent.verify_inbox() if you do not know the message ID)", COLOR_INPUT))
            message_id = input(colored("ID: ", COLOR_INPUT))

        # Iterate through messages and print message with message_id
        for message in self.messages:
            if message.message_id == message_id:
                print("\n---------------------------------------------------------------------")
                print(colored("Message received", attrs=["bold"]))
                print("Connection ID : ", message.connection_id)
                print("Message ID : ", message.message_id)
                print("State : ", message.state)
                print("Time : ", message.sent_time)
                print("Text : ", colored(message.content, COLOR_INFO))
                print("---------------------------------------------------------------------")
                return message
        return None

    def get_messages(self) -> list[Optional[Message]]:
        """
        Returns: Get all messages of the agent
        """
        return self.messages

    def verify_inbox(self) -> list[Optional[Message]]:
        """
        Prints all available messages received, grouped by Connection ID
        Returns: list of all message IDs
        """
        print("\n---------------------------------------------------------------------")
        print(colored("Message Inbox", attrs=["bold"]))
        if len(self.messages) == 0:
            print("> Inbox empty")
        else:
            unique_c_ids = [m.connection_id for m in self.messages]
            for c_id in set(unique_c_ids):
                m_ids = [m.message_id for m in self.messages if m.connection_id == c_id]
                print("> {count} Message(s) via Connection ID {cid}:".format(count=unique_c_ids.count(c_id), cid=c_id))
                for m_id in m_ids:
                    print("\t * Message ID : ", m_id)
        print("---------------------------------------------------------------------")
        return [m.message_id for m in self.messages]

    def get_role(self) -> str:
        """
        Get the VC / SSI Role of the agent
        Returns: string decribing the VC / SSI Role of the agent
        """
        return self.role

    def get_agent_listeners(self) -> list[dict]:
        """
        Returns: Get all agent_listeners of the agent
        """
        return self.agent_listeners

    def get_credentials(self):  # @todo: find out which return type this is!
        """
        Get all credentials that the agent controller has stored in their wallet
        Returns: list of all credentials (i.e., VCs)
        """
        loop = asyncio.get_event_loop()
        credentials = loop.run_until_complete(
            self.agent_controller.credentials.get_all()
        )
        return credentials

    def create_connection_invitation(self, alias: Optional[str] = None, auto_accept: bool = True, public: bool = False,
                                     multi_use: bool = False, auto_ping: bool = True) -> Union[str, dict]:
        """
        Creates invitation by agent_controller, and prints the invitation that must be forwarded to an external agent.
        In case arguments are conservative (i.e., auto_accept = False), the function prompts the user to make
        decisions right away whether to accept the external agent's response to the invitation.
        Args:
            alias: Alias name for invited connection
            auto_accept: auto-accept the responses sent by the external agent
            public: Use public DID
            multi_use: Use invitation for multiple invitees
            auto_ping: Automatically ping connection
        Returns: connection_id of invitation
        """
        # Loop until connection is created
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.create_invitation(str(alias).lower(), str(auto_accept).lower(),
                                                                str(public).lower(), str(multi_use).lower())
        )

        # Get connection_id and store as new connection in self (or update existing connection)
        connection_id = invitation_response["connection_id"]
        conn = self._store_connection_id(connection_id, auto_accept, auto_ping, alias)

        # Print invitation to share it with an external agent
        invitation = invitation_response["invitation"]
        print(colored("\nCopy & paste invitation and share with external agent(s):", COLOR_INPUT, attrs=["bold"]))
        pprint(invitation)

        # Return whole invitation if multi_use is true (to be able to store it)
        if multi_use is True:
            return invitation
        # Return only connection_id (as there is only one when multi_use is false)
        else:
            return connection_id

    def receive_connection_invitation(self, alias: Optional[str] = None, auto_accept: bool = True,
                                      auto_ping: bool = True) -> str:
        """
        Function to respond to a connection invitation received by an external agent
        Args:
            alias: name for the connection @todo: verify!
            auto_accept: Automatically accept the reponse by the inviting external agent
            label: @todo: verify!
        Returns: connection_id of connection (as string)
        """
        # Ask user to paste invitation from external agent
        print(colored("Please enter invitation received by external agent:", COLOR_INPUT, attrs=["bold"]))
        invitation = input(colored("Invitation: ", COLOR_INPUT))
        invitation = ast.literal_eval(invitation)  # Convert string invitation from input into a dict

        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.receive_invitation(invitation, alias, str(auto_accept).lower())
        )

        # Get connection_id and store as a new connection in self
        connection_id = invitation_response["connection_id"]
        conn = self._store_connection_id(connection_id, auto_accept, auto_ping, alias)

        # Ask user to accept invitation if auto_accept is set to False
        self._accept_connection_invitation(connection_id, auto_accept=auto_accept)

        return connection_id

    def _accept_connection_invitation(self, connection_id: str, auto_accept: bool = True, label: Optional[str] = None,
                                      endpoint=None) -> None:
        """
        Accept the connection invitation sent by an external agent
        Args:
            connection_id: connection id of invitation
            label: @todo: find out!
            endpoint: @todo: find out!
        Returns: -
        """
        if auto_accept is False:
            choice = get_choice("Accept invitation {c}?".format(c=connection_id),
                                no_text="Please execute agent_controller.connections.accept_invitation(connection_id) to proceed")
            if choice is True:
                # Loop until connection invitation is received
                loop = asyncio.get_event_loop()
                loop.run_until_complete(
                    self.agent_controller.connections.accept_invitation(connection_id, label, endpoint)
                )

    def _accept_invitation_response(self, connection_id: str, auto_accept: bool = True) -> None:
        """
        Accept the response sent by an external agent (usually through _accept_conneciton_invitation) as a result of an invitation sent by the self.agent_controller
        Args:
            connection_id: connection id of the invitation sent
            auto_accept: auto accept invitation or not
        Returns: -
        """
        # Do nothing if auto_accept is True (agent does it automatically)
        # If auto_accept is False, prompt user to accept request
        if auto_accept is False:
            choice = get_choice("Accept invitation request response by external agent?",
                                "Please execute agent_controller._accept_connection_invitation() to proceed")
            if choice is True:
                # Loop until connection invitation is received
                loop = asyncio.get_event_loop()
                loop.run_until_complete(
                    self.agent_controller.connections.accept_request(connection_id)
                )

    def _trust_ping(self, connection_id: str, auto_ping: bool) -> None:
        """
        Send trust_ping to external agent to finalize the connection after sending an invitation
        Args:
            connection_id:
        Returns:
        """
        # @TODO: see if there is some other auto_attribute that needs to be taken into consideration!
        # Prompt user to decide whether to sent a trust ping or not
        if auto_ping is False:
            choice = get_choice("Send trust ping to finalize connection?",
                                no_text="Please execute agent_controller._trust_ping(connection_id) to finalize the connection")
            if choice is True:
                loop = asyncio.get_event_loop()
                loop.run_until_complete(
                    self.agent_controller.messaging.trust_ping(connection_id, "Send trust ping")
                )
        else:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(
                self.agent_controller.messaging.trust_ping(connection_id, "Send automated trust ping")
            )

    def _accept_invitation_request(self, connection_id: str, auto_accept: bool) -> None:
        """
        @todo describe
        Args:
            connection_id:
            auto_accept:

        Returns:
        """
        # Do nothing if auto_accept is True (agent does it automatically)
        # If auto_accept is False, prompt user to accept request
        # @todo: verify why this does not work!!!
        if auto_accept is False:
            # print(colored("Accept invitation request?", COLOR_INPUT))
            # choice = input("Please respond [yes/no] ")
            # choice = True if choice == "yes" else False
            #
            # #choice = get_choice("Accept invitation request?", "Did not accept invitation request.")
            # if choice is True:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(
                self.agent_controller.connections.accept_request(connection_id)
            )

    def send_message(self, connection_id: str, basic_message: str) -> None:
        """
        Send basic message between agent and another external agent at the other end of the connection
        Args:
            connection_id: id of connection over which to send a message
            basic_message: message to be sent via conneciton with connection_id
        Returns: -
        """
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.messaging.send_message(connection_id, basic_message)
        )
        print("Sent message via Connection ID {cid}".format(cid=connection_id))

    def _connections_handler(self, payload: TypeDict) -> None:
        """
        @todo: describe connections handler!
        Args:
            payload:

        Returns:

        """

        state = payload['state']
        connection_id = payload["connection_id"]
        their_role = payload["their_role"]
        routing_state = payload["routing_state"]
        rfc_state = payload["rfc23_state"]

        # Register new connection_id if it does not yet exist
        if "alias" in payload:
            conn = self._store_connection_id(connection_id, alias=payload["alias"])
        else:
            conn = self._store_connection_id(connection_id)

        print("\n---------------------------------------------------------------------")
        print(colored("Connection Webhook Event Received: Connections Handler", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("State : ", colored("{s} ({r})".format(s=state, r=rfc_state), COLOR_INFO))
        print("Routing State : {routing}".format(routing=routing_state))
        if 'their_label' in payload:
            their_label = payload['their_label']
            print(f"Connection with : ", their_label)
            conn.connection_with = their_label
        print("Their Role : ", their_role)
        print("---------------------------------------------------------------------")

        if state == "active":
            conn.is_active = True
            print(colored("\nConnection ID: {0} is now active".format(connection_id), COLOR_SUCCESS, attrs=["bold"]))
        elif rfc_state == "invitation-received":
            self._accept_invitation_response(connection_id, conn.auto_accept)
        elif rfc_state == "response-received":
            self._trust_ping(connection_id, conn.auto_ping)
        elif rfc_state == "request-received":
            self._accept_invitation_request(connection_id, conn.auto_accept)

    def _messages_handler(self, payload: TypeDict) -> None:
        """
        @todo: describe!
        Args:
            payload:

        Returns:

        """
        message = Message(payload)
        self.messages.append(message)


class RelyingParty(AgentConnectionManager):

    def __init__(self, agent_controller: AriesAgentController) -> None:
        super(RelyingParty, self).__init__(agent_controller)
        self.role = "RelyingParty"
        self.agent_listeners.append({"topic": "present_proof", "handler": self._relying_party_proof_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

    def send_proof_request(self, connection_id: str, proof_request: TypeDict, comment: str) -> str:
        """
        @todo
        Args:
            connection_id: connection_id over which to request a proof
            comment: comment for external agent
            proof_request: dictionary with proof request information

        Returns: presentation_exchange_id (needed to proceed with exchange of proof presentation)

        """
        # Define entire request that will be sent to the external agent
        whole_request = {
            "comment": comment,
            "connection_id": connection_id,
            "proof_request": proof_request,
            "trace": False
        }

        # Await response from sending the request
        loop = asyncio.get_event_loop()
        proof_req_response = loop.run_until_complete(
            self.agent_controller.proofs.send_request(whole_request)
        )

        return proof_req_response["presentation_exchange_id"]

    def verify_proof_presentation(self, presentation_exchange_id: str) -> bool:
        """
        Verify if the proof presentation sent by an external agent is valid
        Args:
            presentation_exchange_id: id of presentation to be verified

        Returns: whether proof presentation is valid or not

        """
        loop = asyncio.get_event_loop()
        verified_response = loop.run_until_complete(
            self.agent_controller.proofs.verify_presentation(presentation_exchange_id)
        )

        print("\n---------------------------------------------------------------------")
        print(colored("Presentation Exchange ID {pei}".format(pei=presentation_exchange_id), attrs=["bold"]))

        # Print verified status
        verified = bool(verified_response["verified"])  # States whether the proof is valid or not
        verified_color = COLOR_SUCCESS if verified is True else COLOR_ERROR
        print("Presentation valid : ", colored(verified, verified_color))

        # Parse revealed attributes
        print("Revealed Attributes : ")
        for (name, val) in verified_response['presentation']['requested_proof']['revealed_attrs'].items():
            attr_name = verified_response["presentation_request"]["requested_attributes"][name]["name"]
            print("\t* {a} = {r}".format(a=attr_name, r=val['raw']))

        # Parse self-attested attributes
        print("Self-Attested Attributes : ")
        for (name, val) in verified_response['presentation']['requested_proof']['self_attested_attrs'].items():
            print("\t* {n} = {v}".format(n=name, v=val))

        # Parse predicate attributes
        print("Predicate Attributes : ")
        for (name, val) in verified_response['presentation']['requested_proof']['predicates'].items():
            print("\t* {n} = {v}".format(n=name, v=val))
        print("---------------------------------------------------------------------")

        return verified

    def _relying_party_proof_handler(self, payload: TypeDict) -> None:
        """
        @todo: fill out!
        Args:
            payload:

        Returns:

        """
        role = payload["role"]
        connection_id = payload["connection_id"]
        pres_ex_id = payload["presentation_exchange_id"]
        state = payload["state"]

        print("\n---------------------------------------------------------------------")
        print(colored("Connection Webhook Event Received: Present-Proof Handler", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("Presentation Exchange ID : ", pres_ex_id)
        print("Protocol State : ", colored("{s}".format(s=state), COLOR_INFO))
        print("Agent Role : ", role)
        print("Initiator : ", payload["initiator"])
        print("---------------------------------------------------------------------")

        # Store presentation_exchange_id to connection
        conn = self.get_connection(connection_id)
        if pres_ex_id not in conn.presentation_exchange_ids:
            conn.presentation_exchange_ids.append(pres_ex_id)

        if state == "request_sent":
            print(colored("\nPresentation Request : ", attrs=["bold"]))
            pprint(payload["presentation_request_dict"])

        elif state == "verified":
            print(colored("\nPresentation Exchange ID: {pei} is verified".format(pei=pres_ex_id), COLOR_SUCCESS,
                          attrs=["bold"]))


class CredentialHolder(AgentConnectionManager):

    def __init__(self, agent_controller: AriesAgentController):
        super(CredentialHolder, self).__init__(agent_controller)
        self.role = "Holder"
        self.agent_listeners.append({"topic": "present_proof", "handler": self._prover_proof_handler})
        self.agent_listeners.append({"topic": "issue_credential", "handler": self._holder_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

    def is_vc_in_wallet(self, vc_referent: str) -> bool:
        """
        Verifies if a verifiable credential named vc is within the wallet of an agent_controller
        Storing a VC is done automatically if ACAPY_AUTO_STORE_CREDENTIAL=true in .env file
        Args:
            vc: referent of verifiable credential
        Returns: True if VC is stored in wallet, False if it is not
        """
        credentials = self.get_credentials()
        if any(result["referent"] == vc_referent for result in credentials["results"]):
            print(colored("Credential {vc} is stored in wallet.".format(vc=vc_referent), COLOR_SUCCESS))
            return True
        else:
            print(colored(
                "\nCredential {vc} is not stored in wallet.".format(
                    vc=vc_referent), COLOR_ERROR))
            return False

    def request_vc(self, connection_id: str, schema_id: str, auto_request: bool = False, auto_store: bool = False,
                   credential_id: Optional[str] = None) -> None:
        """
        Fetch offer made by issuer and request record
        Args:
            auto_store: automatically store VC in wallet if True
            auto_request: automatically request VC if True
            schema_id: id of the schema agent wants a VC for
            connection_id: connection id via which a vc was offered
        Returns: -
        """

        # Get all records to find the offer made by the external agent
        loop = asyncio.get_event_loop()
        records_response = loop.run_until_complete(
            self.agent_controller.issuer.get_records(connection_id)
        )

        # Loop through records to find VC offer for schema_id
        state = None
        for record in records_response["results"]:
            if record["schema_id"] == schema_id:
                state = record["state"]
                record_id = record["credential_exchange_id"]
                break

        # Return if no suitable offered vc was found
        if state != "offer_received":
            print(colored("Could not find requested VC offer", COLOR_ERROR, attrs=["bold"]))
            return None

        # See if user wants to request VC or not
        if auto_request is False:
            print(colored("\nRequest VC from offer", COLOR_INPUT, attrs=["bold"]))
            choice = get_choice("Request VC", "VC will not be requested")
            # Return None if user decided not to request VC
            if choice is False:
                print(colored("Did not request VC", COLOR_ERROR, attrs=["bold"]))
                return None
        else:
            choice = False

        # Send VC request (if conditions are given)
        if (choice is True) or (auto_request is True):
            loop = asyncio.get_event_loop()
            loop.run_until_complete(
                self.agent_controller.issuer.send_request_for_record(record_id)
            )

        # Wait a little bit to see if handler sends message
        time.sleep(3)

        #  Check if VC is stored. If not, store it
        is_in_wallet = self.is_vc_in_wallet(record_id)
        if is_in_wallet is False:
            self._store_vc(record_id, auto_store, credential_id)

    def _store_vc(self, record_id: str, auto_store: bool, referent: Optional[str] = None) -> None:
        """
        Store VC. If auto_store is set to False, the user is prompted whether they want to store the VC or not.
        Args:
            record_id: ID of the VC that should be stored
            auto_store: Does not prompt user to store wallet if True
            referent: alias name for the VC

        Returns:

        """
        # Prompt user to store VC if auto_store is not set to True
        if auto_store is False:
            print(
                colored("\nDo you want to store the VC with ID {i}?".format(i=record_id), COLOR_INPUT, attrs=["bold"]))
            choice = get_choice("Store VC: ", "VC not stored.")

            # Return none if user does not want to store VC
            if choice is False:
                print(colored("VC not stored", COLOR_ERROR, attrs=["bold"]))
                return None

        # Ask for referent if none is given
        if referent is None:
            print(colored("\nPlease provide a referent (like an ID) for the VC", COLOR_INPUT, attrs=["bold"]))
            print(colored("(The referent acts as the identifier for retrieving the raw credential from the wallet)",
                          COLOR_INPUT))
            referent = input(
                colored("Referent: ".format(r=record_id), COLOR_INPUT))

        # Store credential in wallet
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.issuer.store_credential(record_id, referent)
        )
        # @todo: see what types of returns this can get, and only send message if it actually happened...?
        print(colored("Successfully stored credential with Referent {r}".format(r=referent), COLOR_SUCCESS,
                      attrs=["bold"]))

    def prepare_presentation(self, connection_id: str, thread_id: Optional[str] = None,
                             state: str = "request_received", role: str = "prover") -> Tuple[dict, str]:

        # Find all presentation records that were sent to you
        loop = asyncio.get_event_loop()
        proof_records_response = loop.run_until_complete(
            self.agent_controller.proofs.get_records(connection_id, thread_id, state, role)
        )

        # Get most recent presentation_exchange_id and the corresponding proof_request
        conn = self.get_connection(connection_id)
        presentation_exchange_id = conn.presentation_exchange_ids[-1]
        proof_request = \
            [p for p in proof_records_response["results"] if p["presentation_exchange_id"] == presentation_exchange_id][
                0]
        print(colored("> Found proof_request with presentation_exchange_id {pei}".format(pei=presentation_exchange_id),
                      COLOR_INFO))

        # Get requirements from proof_request
        requirements = self._get_proof_request_requirements(proof_request)
        print(colored("> Restrictions for a suitable proof: {r}".format(r=requirements), COLOR_INFO))

        # Compare all VCs in the wallet of the CredentialHolder, and check if one of them satisfies the requirements of the proof_request
        suitable_credentials, revealed = self._get_suitable_vc_for_proof(requirements)

        # Prepare presentation that will be sent to the RelyingParty
        predicates = {}
        self_attested = {}
        presentation = {
            "requested_predicates": predicates,
            "requested_attributes": revealed,
            "self_attested_attributes": self_attested,
        }
        print(colored("> Generate the proof presentation : ", COLOR_INFO))
        pprint(presentation)

        return presentation, presentation_exchange_id

    def send_proof_presentation(self, presentation_exchange_id: str, presentation: dict) -> None:
        """
        Send proof presentation
        Args:
            presentation_exchange_id: id of presentation that should be sent
            presentation: presentation to send

        Returns: -

        """
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.proofs.send_presentation(presentation_exchange_id, presentation)
        )

    def _get_proof_request_requirements(self, presentation_record: dict) -> dict:
        """
        Returns dictionary with {<required-attribute>: <restrictions-of-attribute>} from presentation record
        Args:
            presentation_record: presentation record received

        Returns: dictionary with requirements

        """
        # Setup
        requirements = {}
        presentation_request = presentation_record["presentation_request"]

        # Get required attributes and requirements for the individual attributes
        for attr_key, attr_val in presentation_request["requested_attributes"].items():
            requirements[attr_val["name"]] = {}
            requirements[attr_val["name"]]["requirements"] = attr_val["restrictions"][0]
            requirements[attr_val["name"]]["request_attr_name"] = attr_key

        # @todo: verify if name of manufacturer is requested!?

        return requirements

    def _get_suitable_vc_for_proof(self, requirements: dict) -> Tuple[dict, dict]:
        """
        Finds credentials in credentials_all that satisfy the requirements provided by the relying party.
        Args:
            credentials_all:
            requirements:

        Returns: dictionary with: {<attribute-name>: <suitable-credential>}, where the suitable-credential satisfies all requirements

        """
        # Get all current credentials that will be considered when finding a suitable credential
        loop = asyncio.get_event_loop()
        credentials = loop.run_until_complete(
            self.agent_controller.credentials.get_all()
        )

        # Setup
        relevant_credentials = {}
        revealed = {}
        credentials = credentials_all["results"]

        # Iterate through attribute name and attribute requirements of relying party
        for name, conditions in requirements.items():

            req = conditions["requirements"]
            req_name = conditions["request_attr_name"]

            # Skip credential if the required attribute name is not in any credential,
            # or if all requirements (e.g., schema_id) are not within one credential
            if (any(name in cred["attrs"] for cred in credentials) is False) or (
                    any(r in cred.keys() for r in req for cred in credentials) is False):
                continue

            # Iterate through credentials
            for cred in credentials:
                # Verify if requirement value (r_val) and credential value (cred[r_key]) match for required attribute (r_key)
                for r_key, r_val in req.items():
                    try:
                        # Append cred to relevant_credentials if all requirements match
                        if (cred[r_key] == r_val) is True:
                            relevant_credentials[name] = cred
                            print(colored(
                                "> Attribute request for '{name}' can be satisfied by Credential with VC '{c}'".format(
                                    name=name, c=cred["referent"]), COLOR_INFO))
                            revealed[req_name] = {"cred_id": cred["referent"], "revealed": True}
                    except Exception as e:
                        # @todo: figure out which exception to allow!
                        print(e)

        return relevant_credentials, revealed

    def _holder_handler(self, payload: TypeDict) -> None:
        """
        @todo: fill out!
        Args:
            payload:
        Returns:
        """
        # Get relevant attributes
        connection_id = payload['connection_id']
        exchange_id = payload['credential_exchange_id']
        state = payload['state']
        role = payload['role']

        # Print
        print("\n---------------------------------------------------------------------")
        print(colored("Handle Issue Credential Webhook: Issue Credential Handler", attrs=["bold"]))
        print(f"Connection ID : {connection_id}")
        print(f"Credential exchange ID : {exchange_id}")
        print("Agent Protocol Role : ", role)
        print("Protocol State : ", colored(state, COLOR_INFO))
        print("---------------------------------------------------------------------")

        # Handle different states
        if state == "offer_received":
            proposal = payload["credential_proposal_dict"]["credential_proposal"]
            print(colored("\nProposed Credential : ", attrs=["bold"]))
            pprint(proposal)
        elif state == "credential_acked":
            credential = payload["credential"]
            print(colored("\nReceived Credential :", attrs=["bold"]))
            pprint(credential)

    def _prover_proof_handler(self, payload: TypeDict) -> None:
        """
        @todo: fill out!
        Args:
            payload:
        Returns:
        """
        # Get attributes
        role = payload["role"]
        connection_id = payload["connection_id"]
        pres_ex_id = payload["presentation_exchange_id"]
        state = payload["state"]

        # Print
        print("\n---------------------------------------------------------------------")
        print(colored("Connection Webhook Event Received: Present-Proof Handler", attrs=["bold"]))
        print("Connection ID : ", connection_id)
        print("Presentation Exchange ID : ", pres_ex_id)
        print("Protocol State : ", colored(state, COLOR_INFO))
        print("Agent Role : ", role)
        print("Initiator : ", payload["initiator"])
        print("---------------------------------------------------------------------")

        # Store presentation_exchange_id to connection
        conn = self.get_connection(connection_id)
        if pres_ex_id not in conn.presentation_exchange_ids:
            conn.presentation_exchange_ids.append(pres_ex_id)

        # Handle different states
        if state == "request_received":
            print(colored("Obtained Proof Request : ", attrs=["bold"]))
            pprint(payload["presentation_request"])
        elif state == "presentation_acked":
            print(colored("\nPresentation Exchange ID: {pei} is acknowledged by Relying Party".format(pei=pres_ex_id),
                          COLOR_SUCCESS, attrs=["bold"]))


class IssuingAuthority(AgentConnectionManager):

    def __init__(self, agent_controller: AriesAgentController) -> None:
        super(IssuingAuthority, self).__init__(agent_controller)
        self.role = "Issuing Authority"
        self.agent_listeners.append({"topic": "issue_credential", "handler": self._issuer_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

    def get_did(self) -> Optional[dict]:
        """
        Verifies if an agent already has a public DID or not. If it does not, the function generates a new DID.

        Returns: dictionary with DID information of the agent
        """
        try:
            # Verify if agent already has a public DID
            loop = asyncio.get_event_loop()
            public_did_response = loop.run_until_complete(
                self.agent_controller.wallet.get_public_did()
            )

            # Either use the existing DID
            if public_did_response["result"]:
                did_obj = public_did_response["result"]
                state = "found an existing"
            # Or create a new DID
            else:
                loop = asyncio.get_event_loop()
                create_did_response = loop.run_until_complete(
                    self.agent_controller.wallet.create_did()
                )
                did_obj = create_did_response['result']
                state = "created a new"

            print(colored("Successfully {s} DID:".format(s=state), COLOR_SUCCESS, attrs=["bold"]))
            pprint(did_obj)

            return did_obj

        except Exception as e:
            print(colored("Failed to get DID: ", COLOR_ERROR, attrs=["bold"]), e)
            return None

    def write_did_to_ledger(self, did_obj: dict, url: str = "https://selfserve.sovrin.org/nym",
                            network: str = "stagingnet") -> None:
        """
        Write DID to ledger (by default: Sovrin StagingNet)
        Args:
            did_obj: dictionary with DID information of agent
            url: @todo: check!
            network: @todo: check!
        Returns: -
        """
        # Variables
        payload = {"network": network, "did": did_obj["did"], "verkey": did_obj["verkey"], "paymentaddr": ""}
        headers = {}  # Empty header, because payload includes all information

        # Send request
        r = requests.post(url, data=json.dumps(payload), headers=headers)
        response = r.json()

        # Process response
        status = response["statusCode"]
        body = ast.literal_eval(response["body"])
        reason = body[did_obj["did"]]["reason"]

        # Print response
        text_color = COLOR_SUCCESS if status == 200 else COLOR_ERROR
        print(colored(reason, text_color, attrs=["bold"]))

    def make_did_public(self, did_obj: dict) -> None:
        """
        Assign agent with a public DID if it is not already set as public (can be the case if the containers were not properly shut down)
        Args:
            did_obj: dictionary with DID information of an agent
        Returns: -
        """
        if did_obj["posture"] != "public":
            loop = asyncio.get_event_loop()
            loop.run_until_complete(
                self.agent_controller.wallet.assign_public_did(did_obj["did"])
            )
            print(colored("Successfully initialized agent with Public DID: {d}".format(d=did_obj["did"]), COLOR_SUCCESS,
                          attrs=["bold"]))
        else:
            print("Agent already has Public DID: {d}".format(d=did_obj["did"]))

    def accept_taa_agreement(self) -> None:
        """
        Accept TAA agreement to be able to define schemes and issue VCs as an issuing authority
        Returns: -
        """
        print("--------------------------------- TRANSACTION AUTHOR AGREEMENT (TAA) ---------------------------------")
        print(colored("Source: https://sovrin.org/preparing-for-the-sovrin-transaction-author-agreement/", COLOR_INFO))
        print(colored("Accessed: Aug 16, 2021)", COLOR_INFO))
        print("\n\"As a global public ledger, the Sovrin Ledger and all its participants are subject to privacy")
        print("and data protection regulations such as the EU General Data Protection Regulation (GDPR).")
        print("These regulations require that the participants be explicit about responsibilities for Personal Data.")
        print("\nTo clarify these responsibilities and provide protection for all parties, the Sovrin Governance")
        print("Framework Working Group developed an agreement between Transaction Authors and the Sovrin Foundation.")
        print("The TAA can be found at Sovrin.org. It ensures that users are aware of and consent to the fact that")
        print("all data written to the Sovrin Ledger cannot be removed, even if the original author of the transaction")
        print("requests its removal.")
        print("\nThe TAA outlines the policies that users must follow when interacting with the Sovrin Ledger.")
        print("When a user's client software is preparing a transaction for submission to the network, it must include")
        print("a demonstration that the user had the opportunity to review the current TAA and accept it. This is done")
        print("by including some additional fields in the ledger write transaction:")
        print("\t* A hash of the agreement")
        print("\t* A date when the agreement was accepted, and")
        print("\t* A string indicating the user interaction that was followed to obtain the acceptance.")
        print("\nThe Indy client API used by Sovrin has been extended to allow users to review current and past")
        print("agreements and to indicate acceptance through an approved user interaction pattern.\"")
        print("------------------------------------------------------------------------------------------------------")

        choice = get_choice("Do you accept the TAA?", "You cannot proceed until you accept the TAA.")
        if choice is True:
            try:
                # Get TAA agreement
                loop = asyncio.get_event_loop()
                taa_response = loop.run_until_complete(
                    self.agent_controller.ledger.get_taa()
                )
                TAA = taa_response['result']['taa_record']

                # Accept TAA
                TAA['mechanism'] = "service_agreement"
                loop = asyncio.get_event_loop()
                loop.run_until_complete(
                    self.agent_controller.ledger.accept_taa(TAA)
                )

                print(colored("Successfully signed TAA agreement", COLOR_SUCCESS, attrs=["bold"]))

            except Exception as e:
                print(colored("Failed to accept TAA agreement: ", COLOR_ERROR, attrs=["bold"]), e)
        else:
            print(
                colored("Cannot define schemes nor issue VCs if the TAA is not accepted", COLOR_ERROR, attrs=["bold"]),
                e)

    def write_vc_schema(self, schema_name: str, schema_version: str, attributes: list) -> Optional[str]:
        """
        Writes and defines schema that the issuing authority will be able to issue
        Args:
            schema_name: name of the schema
            schema_version: version of the schema
            attributes: list of attributes that are part of the schema
        Returns: schema_id
        """
        # Write schema and await response
        try:
            # Write schema to agent
            loop = asyncio.get_event_loop()
            response = loop.run_until_complete(
                self.agent_controller.schema.write_schema(schema_name, attributes, schema_version)
            )

            # Process response
            schema_id = response["schema_id"]
            print(colored("Successfully wrote {n} schema:".format(n=schema_name), COLOR_SUCCESS, attrs=["bold"]))
            pprint(response)
            return schema_id
        except Exception as e:
            print(colored("Failed to write {n} schema: ".format(n=schema_name), COLOR_ERROR, attrs=["bold"]), e)
            return None

    def write_vc_cred_def(self, schema_id: str, tag: str = "default", support_revocation: bool = False) -> str:
        """
        Writes credential definition transaction to the public ledger to speecify the public cryptographic
        material the agent uses to sign all credentials issued against schema with schema_id
        Args:
            schema_id: id of schema
            tag: @todo: find out!
            support_revocation: make credential definition support revokation. requires ACAPY_TAILS_SERVER_BASE_URL env
                                variable to be properly configured
        Returns: credential definition id as string
        """
        loop = asyncio.get_event_loop()
        cred_def_response = loop.run_until_complete(
            self.agent_controller.definitions.write_cred_def(schema_id, tag, support_revocation)
        )

        cred_def_id = cred_def_response["credential_definition_id"]
        print(colored("Successfully wrote credential definition id: {cdef}".format(cdef=cred_def_id)))
        return cred_def_id

    def offer_vc(self, connection_id: str, schema_id: str, cred_def_id: str,
                 credential_attributes: Optional[list] = None, comment: Optional[str] = None,
                 auto_remove: bool = True, trace: bool = False) -> None:
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
        Returns: -
        """
        # Get schema information from issuing authority by ID of schema
        loop = asyncio.get_event_loop()
        schema_info = loop.run_until_complete(
            self.agent_controller.schema.get_by_id(schema_id)
        )

        # Prompt user to enter credential attributes if they were not passed as an argument
        if credential_attributes is None:
            # Get list of attributes required by schema
            attributes = schema_info["schema"]["attrNames"]
            # Loop data input until user is happy with the data
            happy = False
            while happy is False:
                print(colored("Please enter the following information for the {n} scheme: ".format(
                    n=schema_info["schema"]['name']), COLOR_INPUT, attrs=["bold"]))
                credential_attributes = []
                for attr in attributes:
                    value = input(colored("{n}: ".format(n=attr), COLOR_INPUT))
                    credential_attributes.append({"name": attr, "value": value})
                # Ask user if the data was entered correctly
                happy = get_choice("Is the information correct?", "Please enter the information again.")

        # Send credential to external agent at the other end of the connection_id if all data is collected
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.issuer.send_credential(connection_id, schema_id, cred_def_id, credential_attributes,
                                                         comment, auto_remove, trace)
        )

    def _issuer_handler(self, payload: TypeDict) -> None:
        """
        Handles the payload for the Issuing Authority when issuing a verifiable credential
        Args:
            payload: @todo: find out!
        Returns: -
        """
        # Attributes
        connection_id = payload['connection_id']
        exchange_id = payload['credential_exchange_id']
        state = payload['state']
        role = payload['role']

        # Print
        print("\n---------------------------------------------------------------------")
        print(colored("Handle Issue Credential Webhook: Issue Credential Handler", attrs=["bold"]))
        print(f"Connection ID : {connection_id}")
        print(f"Credential exchange ID : {exchange_id}")
        print("Agent Protocol Role : ", role)
        print("Protocol State : ", colored(state, COLOR_INFO))
        print("---------------------------------------------------------------------")

        # Handle different states
        if state == "offer_sent":
            offer = payload["credential_proposal_dict"]['credential_proposal']
            print(colored("\nProposed Credential : ", attrs=["bold"]))
            pprint(offer)
