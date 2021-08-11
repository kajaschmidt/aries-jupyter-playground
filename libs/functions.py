from aries_cloudcontroller import AriesAgentController
import ast
import asyncio
import json
from pprintpp import pprint
import requests
from termcolor import colored


async def is_vc_in_wallet(agent_controller: AriesAgentController, vc: str):
    """
    Verifies if a verifiable credential named vc is within the wallet of an agent_controller
    Args:
        agent_controller: AriesAgentController
        vc: verifiable credential
    Returns: -
    """
    credentials = await agent_controller.credentials.get_all()
    if any(result["referent"] == vc for result in credentials["results"]):
        print(colored("Credential {vc} already in wallet. Please proceed.".format(vc=vc), "green", attrs=["bold"]))
    else:
        print(colored("Credential {vc} not found in wallet. Please execute the notebooks of the authority agent first.".format(vc=vc), "red", attrs=["bold"]))


def get_identifiers() -> dict:
    """
    Opens identifiers.json file to get newest scheme_id, cred_def_id, and authority_did as defined in the
    authority agent's init_authority_as_issuer.ipynb notebook
    Returns: (dict) relevant identifiers
    """
    with open("libs/identifiers.json") as f:
        identifiers = json.load(f)
        f.close()
    return identifiers


def store_identifiers(identifiers: dict):
    """
    Writes dict with newest scheme_id, cred_def_id, and authority_did to identifiers.json as defined in the
    authority agent's init_authority_as_issuer.ipynb notebook
    Args:
        identifiers: (dict) contains newe

    Returns: -

    """
    with open("libs/identifiers.json", "w") as fp:
         json.dump(identifiers, fp,  indent=4)
    print(colored("Successfully stored identifiers dictionary in libs/identifiers.json.", "green", attrs=["bold"]), "(Will be needed in other notebooks and by other agents.)")
    pprint(identifiers)

    
async def get_public_did(agent_controller):
    
    try: # Await public_did_response
        public_did_response = await agent_controller.wallet.get_public_did()

        # Use existing DID, or create a new one
        if public_did_response["result"]:
            did_obj = public_did_response["result"]
        else:
            create_did_response = await agent_controller.wallet.create_did()
            did_obj = create_did_response['result']
       
        print(colored("Successfully got public DID", "green", attrs=["bold"]))
        pprint(did_obj)
        
        return did_obj
    
    except Exception as e:
        print(colored("Failed to get public DID: ", "red", attrs=["bold"]), e)
        
        
def write_did_to_ledger(did_obj, url="https://selfserve.sovrin.org/nym", network="stagingnet"):
    # Variables
    payload = {"network":network,"did": did_obj["did"], "verkey":did_obj["verkey"], "paymentaddr":""}
    headers = {} # Empty header, because payload includes all information

    # Send request
    r = requests.post(url, data=json.dumps(payload), headers=headers)
    response = r.json()
    status = response["statusCode"]
    body = ast.literal_eval(response["body"])
    reason = body[did_obj["did"]]["reason"]
    
    text_color = "green" if status == 200 else "red"
    print("Status : ", colored(status, text_color, attrs=["bold"]))
    print("Reason : ", reason)
    
    
async def accept_taa_agreement(agent_controller):
    
    try:
        # Get TAA agreement
        taa_response = await agent_controller.ledger.get_taa()
        TAA = taa_response['result']['taa_record']

        # Accept TAA
        TAA['mechanism'] = "service_agreement"
        await agent_controller.ledger.accept_taa(TAA)
        
        print(colored("Successfully signed TAA agreement", "green", attrs=["bold"]))
    
    except Exception as e:
        print(colored("Failed to accept TAA agreement: ", "red", attrs=["bold"]), e)
    

async def write_schema(
        agent_controller: AriesAgentController, schema_name: str, schema_version: str, attributes: list
):
    # Write schema and await response
    try:
        response = await agent_controller.schema.write_schema(schema_name, attributes, schema_version)

        schema_manufacturer_id = response["schema_id"]
        print(colored("Successfully wrote {n} schema:".format(n=schema_name), "green", attrs=["bold"]))
        pprint(response)

        return schema_manufacturer_id
    except Exception as e:
        print(colored("Failed to write {n} schema: ".format(n=schema_name), "red", attrs=["bold"]), e)


async def create_invitation(agent_controller: AriesAgentController, alias, auto_accept: str, public: str, multi_use: str):
    """
    Creates invitation by agent_controller, and prints the invitation that must be forwarded to an external agent
    Args:
        agent_controller: agent controller who initiates an invitation
        alias: @todo: figure out!
        auto_accept: auto-accept the responses sent by the external agent
        public: @todo: figure out!
        multi_use: allow use of invitation by multiple agents multiple times

    Returns: - (prints invitation)

    """
    invite = await agent_controller.connections.create_invitation(alias, auto_accept, public, multi_use)
    invitation = invite["invitation"]
    print(colored("\nCopy & paste invitation and share with external agent:", "blue", attrs=["bold"]))
    pprint(invitation)
    print("\n")



