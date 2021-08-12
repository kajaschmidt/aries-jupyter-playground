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

class AgentConnectionManager:
    def __init__(
            self,
            agent_controller: AriesAgentController,
            role: str,
    ) -> None:

        self.agent_controller = agent_controller
        self.agent_listeners = [
            {"topic": "connections", "handler": self._connections_handler},
            {"topic": "basicmessages", "handler": self._messages_handler},
        ]
        if role == "holder":
            self.agent_listeners.append({"topic": "present_proof", "handler": self._prover_proof_handler})
            self.agent_listeners.append({"topic": "issue_credential", "handler": self._holder_handler})
        elif role == "relying_party":
            self.agent_listeners.append({"topic": "present_proof", "handler": self._verifier_proof_handler})
        elif role == "issuer":
            self.agent_listeners.append({"topic": "issue_credential", "handler": self._issuer_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        self.connections: [Connection] = []

        listener_topics = [s["topic"] for s in self.agent_listeners]

        print(colored("Successfully initiated connection handler for ACA-PY agent", COLOR_SUCCESS, attrs=["bold"]))
        #print(colored("Init AgentConnectionManager:", attrs=["bold"]))
        #print("* Defines and registers agent listeners for {r}: ".format(r=role), listener_topics)
        #print("* Stores initiated connections")
        #print("* Allows to easily create and accept connection invitations")
        #print("* Facilitates process of issuing, verifying, or proving verifiable credentials")

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

    def get_credentials(self):
        loop = asyncio.get_event_loop()
        credentials = loop.run_until_complete(
            self.agent_controller.credentials.get_all()
        )
        return credentials

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
        print(colored("Please enter invitation received by external agent.", COLOR_INPUT, attrs=["bold"]))
        invitation = input(colored("Invitation: ", COLOR_INPUT))
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
            attributes = schema_info["schema"]["attrNames"]
            # Get credential attributes and loop input until user is happy with the data
            happy = False
            while happy is False:
                print(colored("Please enter the following information for the {n} scheme (ID: {id}): ".format(n=schema_info["schema"]['name'], id=schema_id), COLOR_INPUT, attrs=["bold"]))
                credential_attributes = []
                for attr in attributes:
                    value = input(colored("{n}: ".format(n=attr), COLOR_INPUT))
                    credential_attributes.append({"name": attr, "value": value})
                happy = get_choice("Is the information correct?", "Please enter the information again.")

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.issuer.send_credential(connection_id, schema_id, cred_def_id, credential_attributes, comment, auto_remove, trace)
        )


    def request_vc(self, connection_id: str, schema_id: str, credential_id=None, role="prover", thread_id=None):
        """
        Fetch offer made by issuer and request record
        Args:
            connection_id: connection id via which a vc was offered
            state: state denoting an offer was received
            role: role of the agent
            thread_id: @todo: find out!

        Returns:

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
                print("Found record for {s} at state {state}".format(s=schema_id, state=state))
                break

        # Return if no suitable offered vc was found
        if state != "offer_received":
            return None

        # send request for VC that was offered
        loop = asyncio.get_event_loop()
        await_record = loop.run_until_complete(
            self.agent_controller.issuer.send_request_for_record(record_id)
        )

        #@todo: manage over holder_handler!
        print(colored("Found credential with ID {i}".format(i=record_id), COLOR_SUCCESS))
        print("Offer : ")
        pprint(await_record["credential_proposal_dict"])

        # Therefore: check if VC is stored, else ask if it should be stored.
        is_in_wallet = self.is_vc_in_wallet(record_id)

        if is_in_wallet is False:
            choice = get_choice("Do you want to store the VC with ID {i}".format(i=record_id), "Please store the VC by executing connections._store_vc()")
            if choice is True:
                self._store_vc(record_id, credential_id)

    def is_vc_in_wallet(self, vc: str):
        """
        Verifies if a verifiable credential named vc is within the wallet of an agent_controller
        Storing a VC is done automatically if ACAPY_AUTO_STORE_CREDENTIAL=true in .env file
        Args:
            vc: verifiable credential
        Returns: -
        """
        credentials = self.get_credentials()

        print("credentials:")
        pprint(credentials)

        #@todo: check if this is the correct way to filter with referent!
        if any(result["referent"] == vc for result in credentials["results"]):
            print(colored("Credential {vc} is stored in wallet.".format(vc=vc), COLOR_SUCCESS, attrs=["bold"]))
            return True
        else:
            print(colored(
                "Credential {vc} is not stored in wallet.".format(
                    vc=vc), COLOR_ERROR, attrs=["bold"]))
            return False

    def _store_vc(self, record_id: str, credential_id=None):

        if credential_id is None:
            credential_id = input(colored("Please provide a Credential ID for VC with Record ID {r}".format(r=record_id), COLOR_INPUT))

        loop = asyncio.get_event_loop()
        store_cred_response = loop.run_until_complete(
            self.agent_controller.issuer.store_credential(record_id, credential_id)
        )

        #@todo: manage over holder_handler!
        print(colored("Successfully stored credential (Credential ID: {c})".format(c=credential_id), COLOR_SUCCESS, attrs=["bold"]))

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
            print(f"Offering :")
            pprint(attributes)
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
        print(payload)
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

    def _holder_handler(self, payload):
        connection_id = payload['connection_id']
        exchange_id = payload['credential_exchange_id']
        state = payload['state']
        role = payload['role']
        print("\n---------------------------------------------------\n")
        print("Handle Issue Credential Webhook")
        print(f"Connection ID : {connection_id}")
        print(f"Credential exchange ID : {exchange_id}")
        print("Agent Protocol Role : ", role)
        print("Protocol State : ", state)
        print("\n---------------------------------------------------\n")
        print("Handle Credential Webhook Payload")

        if state == "offer_received":
            print("Credential Offer Recieved")
            proposal = payload["credential_proposal_dict"]
            print(
                "The proposal dictionary is likely how you would understand and display a credential offer in your application")
            print("\n", proposal)
            print("\n This includes the set of attributes you are being offered")
            attributes = proposal['credential_proposal']['attributes']
            print(attributes)
            ## YOUR LOGIC HERE
        elif state == "request_sent":
            print(
                "\nA credential request object contains the commitment to the agents master secret using the nonce from the offer")
            ## YOUR LOGIC HERE
        elif state == "credential_received":
            print("Received Credential")
            ## YOUR LOGIC HERE
        elif state == "credential_acked":
            ## YOUR LOGIC HERE
            credential = payload["credential"]
            print("Credential Stored\n")
            print(credential)

            print("\nThe referent acts as the identifier for retrieving the raw credential from the wallet")
            # Note: You would probably save this in your application database
            credential_referent = credential["referent"]
            print("Referent", credential_referent)

