from aries_cloudcontroller import AriesAgentController
import asyncio
from pprintpp import pprint
from termcolor import colored


# Global connection ID to enable the use of an multi-use invite to M1, M2, M3
# This way, CONNECTION_ID is updated depending on who connects with the City agent
# @TODO: See if you can specify the connection ID for the city agent!
global CONNECTION_ID

# Receive connection messages
def connections_handler(payload):
    """

    Args:
        payload:

    Returns:

    """
    global CONNECTION_ID

    state = payload['state']
    connection_id = payload["connection_id"]
    their_role = payload["their_role"]
    routing_state = payload["routing_state"]
    rfc_state = payload["rfc23_state"]

    print(colored("\n---------------------------------------------------------------------", attrs=["bold"]))
    print(colored("Connection Webhook Event Received", attrs=["bold"]))
    print("Connection ID : ", connection_id)
    print("State : ", colored(state, "yellow"))
    print("Routing State : {routing} ({rfc})".format(routing=routing_state, rfc=rfc_state))
    if 'their_label' in payload:
        print(f"Connection with : ", payload['their_label'])
    print("Their Role : ", their_role)
    print(colored("---------------------------------------------------------------------", attrs=["bold"]))

    if state == "invitation":
        # Your business logic
        # print("invitation")
        CONNECTION_ID = connection_id

    # elif state == "request":
    # Your business logic
    # print("request")

    # elif state == "response":
    # Your business logic
    # print("response")

    elif state == "active":
        # Your business logic
        print(colored("Connection ID: {0} is now active.".format(connection_id), "green", attrs=["bold"]))
        
        
def issuer_handler(payload):
    connection_id = payload['connection_id']
    exchange_id = payload['credential_exchange_id']
    state = payload['state']
    role = payload['role']
    
    print(colored("\n---------------------------------------------------------------------", attrs=["bold"]))
    print(colored("Handle Issue Credential Webhook", attrs=["bold"]))
    print(f"Connection ID : {connection_id}")
    print(f"Credential exchange ID : {exchange_id}")
    print("Agent Protocol Role : ", role)
    print("Protocol State : ", colored(state, "yellow") )
    print(colored("---------------------------------------------------------------------", attrs=["bold"]))
    
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
        
        
def messages_handler(payload):
    connection_id = payload["connection_id"]
    print("Handle message", connection_id)
    pprint(payload)


def prover_proof_handler(payload):
    """

    Args:
        payload:

    Returns:

    """
    role = payload["role"]
    connection_id = payload["connection_id"]
    pres_ex_id = payload["presentation_exchange_id"]
    state = payload["state"]
    print(colored("\n---------------------------------------------------------------------", attrs=["bold"]))
    print(colored("Handle present-proof", attrs=["bold"]))
    print("Connection ID : ", connection_id)
    print("Presentation Exchange ID : ", pres_ex_id)
    print("Protocol State : ", state)
    print("Agent Role : ", role)
    print("Initiator : ", payload["initiator"])
    print(colored("---------------------------------------------------------------------", attrs=["bold"]))

    if state == "request_received":
        presentation_request = payload["presentation_request"]
        print("Recieved Presentation Request\n")
        print("\nRequested Attributes - Note the restrictions. These limit the credentials we could respond with\n")
        print(presentation_request["requested_attributes"])
    elif state == "presentation_sent":
        print("Presentation sent\n")

    elif state == "presentation_acked":
        print("Presentation has been acknowledged by the Issuer")


def verifier_proof_handler(payload):
    """

    Args:
        payload:

    Returns:

    """
    role = payload["role"]
    connection_id = payload["connection_id"]
    pres_ex_id = payload["presentation_exchange_id"]
    state = payload["state"]
    print(colored("\n---------------------------------------------------------------------", attrs=["bold"]))
    print(colored("Handle present-proof", attrs=["bold"]))
    print("Connection ID : ", connection_id)
    print("Presentation Exchange ID : ", pres_ex_id)
    print("Protocol State : ", state)
    print("Agent Role : ", role)
    print("Initiator : ", payload["initiator"])
    print(colored("---------------------------------------------------------------------", attrs=["bold"]))

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
