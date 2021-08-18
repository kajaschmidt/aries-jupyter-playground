# stdlib
import ast
import asyncio
import json
import logging
import nest_asyncio
import qrcode
import requests
import time
from aries_cloudcontroller import AriesAgentController
from pprintpp import pprint
from termcolor import colored
from typing import Dict as TypeDict
from typing import List as TypeList
from typing import Optional

from .connection import Connection
from .helpers import *
from .message import Message

nest_asyncio.apply()


class AgentConnectionManager:
    def __init__(
            self,
            agent_controller: AriesAgentController,
    ) -> None:
        self.agent_controller = agent_controller
        self.agent_listeners = [
            {"topic": "connections", "handler": self._connections_handler},
            {"topic": "basicmessages", "handler": self._messages_handler},
        ]
        self.connections: [Connection] = []
        self.messages: [Message] = []
        self.role = None

    def get_connection(self, connection_id: str):
        """
        Get connection by connection_id
        Returns: Connection (if it exists) or None
        """
        for connection in self.connections:
            if connection.connection_id == connection_id:
                return connection
        return None

    def get_message(self, message_id: str = None):
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
                break

    def get_messages(self) -> list:
        """
        Returns: Get all messages of the agent
        """
        return self.messages

    def verify_inbox(self) -> list:
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
        return self.role

    def get_agent_listeners(self) -> list:
        """
        Returns: Get all agent_listeners of the agent
        """
        return self.agent_listeners

    def get_connections(self) -> list:
        """
        Returns: Get all connections of the agent
        """
        return self.connections

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

    def create_connection_invitation(self, alias: str = None, auto_accept: bool = True, public: bool = False,
                                     multi_use: bool = False, auto_ping: bool = False) -> str:
        """
        Creates invitation by agent_controller, and prints the invitation that must be forwarded to an external agent.
        In case arguments are conservative (i.e., auto_accept = False), the function prompts the user to make
        decisions right away whether to accept the external agent's response to the invitation.
        Args:
            alias: Alias name for invited connection
            auto_accept: auto-accept the responses sent by the external agent
            public: Use public DID
            multi_use: Use invitation for multiple invitees

        Returns: connection_id of invitation
        """
        # Loop until connection is created
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.create_invitation(str(alias).lower(), str(auto_accept).lower(),
                                                                str(public).lower(), str(multi_use).lower())
        )

        # Get connection_id and store as new connection in self
        connection_id = invitation_response["connection_id"]
        new_connection = Connection(connection_id, auto_accept)
        self.connections.append(new_connection)

        # Print invitation to share it with an external agent
        invitation = invitation_response["invitation"]
        print(colored("\nCopy & paste invitation and share with external agent:", COLOR_INPUT, attrs=["bold"]))
        pprint(invitation)
        print("\n")

        if auto_accept is True:
            self._await_state(connection_id, ["response", "request"])

        else:
            self._await_state(connection_id, ["request"])
            choice = get_choice("Accept invitation request response by external agent?",
                                "Please execute agent_controller._accept_connection_invitation() to proceed")
            if choice is True:
                self._accept_invitation_response(connection_id)

        self._trust_ping(connection_id, auto_ping)
        return connection_id

    def _await_state(self, connection_id: str, awaited_state: list) -> None:
        """
        Loop until an awaited state is reached
        Args:
            awaited_state: state at which the while loop breaks

        Returns: (bool) True if awaited state is reached

        """
        state = None
        while state not in awaited_state:
            loop = asyncio.get_event_loop()
            state_of_invite = loop.run_until_complete(
                self.agent_controller.connections.get_connection(connection_id))
            state = state_of_invite["state"]
            time.sleep(3)  # Add time buffer to limit requests

    def receive_connection_invitation(self, alias: str = None, auto_accept: bool = True, label: str = None) -> str:
        """
        Function to respond to a connection invitation received by an external agent
        Args:
            alias: name for the connection @todo: verify!
            auto_accept: Automatically accept the reponse by the inviting external agent
            label: @todo: verify!

        Returns: connection_id of connection (as string)

        """
        # Ask user to paste invitation from external agent
        print(colored("Please enter invitation received by external agent.", COLOR_INPUT, attrs=["bold"]))
        invitation = input(colored("Invitation: ", COLOR_INPUT))
        invitation = ast.literal_eval(invitation)  # Convert string invitation from input into a dict

        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        invitation_response = loop.run_until_complete(
            self.agent_controller.connections.receive_invitation(invitation, alias, str(auto_accept).lower())
        )

        # Get connection_id and store as a new connection in self
        connection_id = invitation_response["connection_id"]
        new_connection = Connection(connection_id)
        self.connections.append(new_connection)

        # Ask user to accept invitation if auto_accept is set to False
        if auto_accept is False:
            choice = get_choice("Accept invitation {c}?".format(c=connection_id),
                                no_text="Please execute agent_controller.connections.accept_invitation(connection_id) to proceed")
            if choice is True:
                self._accept_connection_invitation(connection_id, label)

        return connection_id

    def _accept_connection_invitation(self, connection_id: str, label: str = None, endpoint=None) -> None:
        """
        Accept the connection invitation sent by an external agent
        Args:
            connection_id: connection id of invitation
            label: @todo: find out!
            endpoint: @todo: find out!

        Returns: -

        """
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.connections.accept_invitation(connection_id, label, endpoint)
        )

    def _accept_invitation_response(self, connection_id: str) -> None:
        """
        Accept the response sent by an external agent (usually through _accept_conneciton_invitation) as a result of an invitation sent by the self.agent_controller
        Args:
            connection_id: connection id of the invitation sent

        Returns: -
        """

        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            self.agent_controller.connections.accept_request(connection_id)
        )

    def _trust_ping(self, connection_id: str, auto_ping: bool = False) -> None:
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

    def send_message(self, connection_id: str, basic_message: str):
        """
        Send basic message between agent and another external agent at the other end of the connection
        Args:
            connection_id: id of connection over which to send a message
            basic_message: message to be sent via conneciton with connection_id

        Returns: -

        """
        # Loop until connection invitation is received
        loop = asyncio.get_event_loop()
        message_response = loop.run_until_complete(
            self.agent_controller.messaging.send_message(connection_id, basic_message)
        )
        print("Sent message via Connection ID {cid}".format(cid=connection_id))
        # @todo: harmonize with message_handler!

    # Connection handlers
    def _connections_handler(self, payload: TypeDict):

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

    def _messages_handler(self, payload: TypeDict):
        message = Message(payload)
        self.messages.append(message)


class RelyingParty(AgentConnectionManager):
    def __init__(
            self,
            agent_controller: AriesAgentController,
    ):
        super(RelyingParty, self).__init__(agent_controller)
        self.role = "RelyingParty"
        self.agent_listeners.append({"topic": "present_proof", "handler": self._relying_party_proof_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

        def _relying_party_proof_handler(self, payload: TypeDict):
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
                print("Payload \n")
                print(payload)


class CredentialHolder(AgentConnectionManager):
    def __init__(
            self,
            agent_controller: AriesAgentController,
    ):
        super(CredentialHolder, self).__init__(agent_controller)
        self.role = "Holder"
        self.agent_listeners.append({"topic": "present_proof", "handler": self._prover_proof_handler})
        self.agent_listeners.append({"topic": "issue_credential", "handler": self._holder_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

    def is_vc_in_wallet(self, vc: str):
        """
        Verifies if a verifiable credential named vc is within the wallet of an agent_controller
        Storing a VC is done automatically if ACAPY_AUTO_STORE_CREDENTIAL=true in .env file
        Args:
            vc: referent of verifiable credential
        Returns: -
        """
        credentials = self.get_credentials()

        # @todo: check if this is the correct way to filter with referent!
        if any(result["referent"] == vc for result in credentials["results"]):
            print(colored("Credential {vc} is stored in wallet.".format(vc=vc), COLOR_SUCCESS))
            return True
        else:
            print(colored(
                "\nCredential {vc} is not stored in wallet.".format(
                    vc=vc), COLOR_ERROR))
            return False

    def request_vc(self, connection_id: str, schema_id: str, auto_request: bool=False, auto_store: bool = False, credential_id: str = None, thread_id=None):
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
                #print(colored("Found credential offer for {s} at state {state}".format(s=schema_id, state=state), COLOR_INFO))
                break

        # Return if no suitable offered vc was found
        if state != "offer_received":
            return None

        if auto_request is False:
            print(colored("\nRequest VC from offer", COLOR_INPUT, attrs=["bold"]))
            choice = get_choice("Request VC", "VC will not be requested")
        else:
            choice = False

        if (choice is True) or (auto_request is True):
            # send request for VC that was offered
            loop = asyncio.get_event_loop()
            await_record = loop.run_until_complete(
                self.agent_controller.issuer.send_request_for_record(record_id)
            )

        # Wait a little bit to see if handler sends message
        time.sleep(3)

        # Therefore: check if VC is stored, else ask if it should be stored.
        is_in_wallet = self.is_vc_in_wallet(record_id)

        if (is_in_wallet is False) and (auto_store is True):
            self._store_vc(record_id, credential_id)
        elif is_in_wallet is False:
            print(colored("\nDo you want to store the VC with ID {i}?".format(i=record_id), COLOR_INPUT, attrs=["bold"]))
            choice = get_choice("Store VC: ", "Please store the VC by executing connections._store_vc()")
            if choice is True:
                self._store_vc(record_id, credential_id)

    def _store_vc(self, record_id: str, credential_id=None):

        if credential_id is None:
            print(colored("\nPlease provide a referent (Credential ID) for VC", COLOR_INPUT, attrs=["bold"]))
            print(colored("(The referent acts as the identifier for retrieving the raw credential from the wallet)", COLOR_INPUT))
            credential_id = input(
                colored("Referent: ".format(r=record_id), COLOR_INPUT))
        loop = asyncio.get_event_loop()
        store_cred_response = loop.run_until_complete(
            self.agent_controller.issuer.store_credential(record_id, credential_id)
        )

        # @todo: manage over holder_handler!
        print(colored("\nSuccessfully stored credential (Credential ID: {c})".format(c=credential_id), COLOR_SUCCESS,
                      attrs=["bold"]))

    def _holder_handler(self, payload: TypeDict) -> None:
        """
        @todo: fill out!
        Args:
            payload:

        Returns:

        """
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
        if state == "offer_received":
            proposal = payload["credential_proposal_dict"]["credential_proposal"]
            print("Proposed Credential : ")
            pprint(proposal)
        print("---------------------------------------------------------------------")

        if state == "request_sent":
            print("REQUEST SENT")
        elif state == "credential_acked":
            ## YOUR LOGIC HERE
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


class IssuingAuthority(AgentConnectionManager):
    def __init__(
            self,
            agent_controller: AriesAgentController,
            # role: str,
    ) -> None:
        super(IssuingAuthority, self).__init__(agent_controller)
        self.role = "Issuing Authority"
        self.agent_listeners.append({"topic": "issue_credential", "handler": self._issuer_handler})
        self.agent_controller.register_listeners(self.agent_listeners, defaults=False)
        print(
            colored("Successfully initiated AgentConnectionManager for a(n) {role} ACA-PY agent".format(role=self.role),
                    COLOR_SUCCESS, attrs=["bold"]))

    def get_did(self) -> dict:
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

    def write_did_to_ledger(self, did_obj, url="https://selfserve.sovrin.org/nym", network="stagingnet") -> None:
        """
        Write DID to ledger (by default: Sovrin StagingNet)
        Args:
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

        text_color = COLOR_SUCCESS if status == 200 else COLOR_ERROR
        # print("Status : ", colored(status, text_color, attrs=["bold"]))
        # print("Reason : ", reason)
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
            response = loop.run_until_complete(
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
        print(
            "-------------------------------------- TRANSACTION AUTHOR AGREEMENT (TAA) --------------------------------------")
        print(colored(
            "\nSource: https://sovrin.org/preparing-for-the-sovrin-transaction-author-agreement/ (accessed Aug 16, 2021)",
            COLOR_INFO))
        print(
            "\n\"As a global public ledger, the Sovrin Ledger and all its participants are subject to privacy and data")
        print(
            "protection regulations such as the EU General Data Protection Regulation (GDPR). These regulations require")
        print("that the participants be explicit about responsibilities for Personal Data. ...")
        print(
            "\nTo clarify these responsibilities and provide protection for all parties, the Sovrin Governance Framework")
        print("Working Group developed an agreement between Transaction Authors and the Sovrin Foundation. The TAA can")
        print(
            "be found at Sovrin.org. It ensures that users are aware of and consent to the fact that all data written")
        print(
            "to the Sovrin Ledger cannot be removed, even if the original author of the transaction requests its removal.")
        print(
            "\nThe TAA outlines the policies that users must follow when interacting with the Sovrin Ledger. When a user’s")
        print(
            "client software is preparing a transaction for submission to the network, it must include a demonstration that")
        print(
            "the user had the opportunity to review the current TAA and accept it. This is done by including some additional")
        print("fields in the ledger write transaction:")
        print("\t* A hash of the agreement")
        print("\t* A date when the agreement was accepted, and")
        print("\t* A string indicating the user interaction that was followed to obtain the acceptance.")
        print(
            "\nThe Indy client API used by Sovrin has been extended to allow users to review current and past agreements and")
        print("to indicate acceptance through an approved user interaction pattern.\"")
        print(
            "----------------------------------------------------------------------------------------------------------------")

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

    def write_vc_schema(self, schema_name: str, schema_version: str, attributes: list) -> str:
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

    def write_vc_cred_def(self, schema_id: str, tag: str = "default", support_revocation: bool = False) -> str:
        """
        Writes credential definition transaction to the public ledger to speecify the public cryptographic
        material the agent uses to sign all credentials issued against schema with schema_id
        Args:
            schema_id: id of schema
            tag: @todo: find out!
            support_revocation: make credential definition support revokation. requires ACAPY_TAILS_SERVER_BASE_URL env variable to be properly configured

        Returns: credential definition id as string

        """
        loop = asyncio.get_event_loop()
        cred_def_response = loop.run_until_complete(
            self.agent_controller.definitions.write_cred_def(schema_id, tag, support_revocation)
        )

        cred_def_id = cred_def_response["credential_definition_id"]
        print(colored("Successfully wrote credential definition id: {cdef}".format(cdef=cred_def_id)))
        return cred_def_id

    def offer_vc(self, connection_id: str, schema_id: str, cred_def_id: str, credential_attributes: list = None,
                 comment: str = None, auto_remove: bool = True, trace: bool = False) -> None:
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
        if state == "offer_sent":
            offer = payload["credential_proposal_dict"]['credential_proposal']
            print("Proposed Credential : ")
            pprint(offer)
        print("---------------------------------------------------------------------")
