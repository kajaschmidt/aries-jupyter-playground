from aries_cloudcontroller import AriesAgentController
from pprintpp import pprint
import json
from termcolor import colored
import asyncio


# Global connection ID to enable the use of an multi-use invite to M1, M2, M3
# This way, CONNECTION_ID is updated depending on who connects with the City agent
global CONNECTION_ID


async def is_vc_in_wallet(agent_controller, vc):
    
    credentials = await agent_controller.credentials.get_all()
    if any(result["referent"] == vc for result in credentials["results"]):
        print("Credential {vc} already in wallet. Please proceed.".format(vc=vc))
    else:
        print("Execute notebooks 00 and 02 to issue a VC to M1!")
        
        
def get_identifiers():
    with open("identifiers.json") as f:
        identifiers = json.load(f)
        f.close()
    return identifiers



# Receive connection messages
def connections_handler(payload):
    global CONNECTION_ID
    
    state = payload['state']
    connection_id = payload["connection_id"]
    their_role = payload["their_role"]
    routing_state = payload["routing_state"]
    rfc_state = payload["rfc23_state"]
    
    print("\n----------------------------------------------------------")
    print("Connection Webhook Event Received")
    print("Connection ID : ", connection_id)
    print("State : ", colored(state, "yellow"))
    print("Routing State : {routing} ({rfc})".format(routing=routing_state, rfc=rfc_state))
    if 'their_label' in payload: 
        print(f"Connection with : ", payload['their_label'])
    print("Their Role : ", their_role)
    print("----------------------------------------------------------")

    if state == "invitation":
        # Your business logic
        #print("invitation")
        CONNECTION_ID = connection_id
        
    #elif state == "request":
        # Your business logic
        #print("request")

    #elif state == "response":
        # Your business logic
        #print("response")
        
    elif state == "active":
        # Your business logic
        print(colored("Connection ID: {0} is now active.".format(connection_id), "green", attrs=["bold"]))

        
        
def prover_proof_handler(payload):
    role = payload["role"]
    connection_id = payload["connection_id"]
    pres_ex_id = payload["presentation_exchange_id"]
    state = payload["state"]
    print("---------------------------------------------------------------------")
    print("Handle present-proof")
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
        
        
        
def verifier_proof_handler(payload):
    role = payload["role"]
    connection_id = payload["connection_id"]
    pres_ex_id = payload["presentation_exchange_id"]
    state = payload["state"]
    print("---------------------------------------------------------------------")
    print("Handle present-proof")
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
        #print("We will not go into detail on this payload as it is comparable to the presentation_sent we looked at in the earlier cell.")
        print("This is the full payload\n")
        print(payload)
    else:
        print("Paload \n")
        print(payload)
        
        
async def create_invitation(agent_controller, alias, auto_accept, public, multi_use):
    invite = await agent_controller.connections.create_invitation(alias, auto_accept, public, multi_use)
    invitation = invite["invitation"]
    print(colored("\nCopy & paste invitation and share with external agent:", "blue", attrs=["bold"]))
    pprint(invitation)
    print("\n")