# Combining Aries ACA-Py and PySyft for Sovereign Data Exchange

This library is the basis of a master thesis to demonstrate how Aries ACA-Py (SSI) and PySyft (SMC) can be combined to enable sovereign data exchange.


## A Jupyter Notebook Based PoC to demonstrate the combination of Self-Sovereign Identity and Secure Multiparty Computation

Design, describe and implement actors and interactions involving the verifiable exchange of information relevant to a specific context. Learn and evaluate what is technically possible using these technologies, validate them for your use case.

This project uses Docker and docker-compose to support and simplify the arbitrary configuration of actors within a SSI ecosystem. As a learner, experimenter or explorer using this playground you get to focus on writing business logic in python through a Jupyter notebook interface that uses the aries-cloudcontroller to interface with the actors respective ACA-Py agent. Either by sending API requests to their exposed Swagger-API or receiving events from this agent posted to a webhook server that you can run within the notebook.


![PoC Architecture](docs/system-architecture.png)

## Requirements

This project is written in Python and is displayed in jupyter notebooks.

You need to install:
1. [Docker](https://docs.docker.com/get-docker/)
2. [docker-compose](https://docs.docker.com/compose/install/)
3. The **source-to-image** (s2i) tool is also required to build the docker images used in the demo. S2I can be downloaded [here](https://github.com/openshift/source-to-image). The website gives instructions for installing on other platforms like MACOS, Linux, Windows.
Verify that **s2i** is in your PATH.  If not, then edit your PATH and add the directory where **s2i** is installed.  The **manage** script will look for the **s2i** executable on your PATH.  If it is not found you will get a message asking you to download and set it on your PATH.
    - If you are using a Mac and have Homebrew installed, the following command will install s2i: `brew install source-to-image`
    - If you are using Linux, go to the [releases](https://github.com/openshift/source-to-image/releases/latest) page and download the correct distribution for your machine. Choose either the linux-386 or the linux-amd64 links for 32 and 64-bit, respectively. Unpack the downloaded tar with `tar -xvf "Release.tar.gz"`
    - If you are not sure about your Operating System you can visit [this](https://whatsmyos.com/) and/or follow the instructions.
    - You should now see an executable called s2i. Either add the location of s2i to your PATH environment variable, or move it to a pre-existing directory in your PATH. For example, `sudo cp /path/to/s2i /usr/local/bin` will work with most setups. You can test it using `s2i version`.

Ensure that Docker is running. If it is not try `sudo dockerd` in another terminal.

## Starting the PoC

This playground comes with five agents that interact with one another: 
* Authority 🏛
* City 🏙️
* Manufacturer1 🚗
* Manufacturer2 🚛
* Manufacturer3 🛵

Each agent has four containers (Aries Agent, Wallet Postgres-DB, Ngrok, and Jupyter Lab). The interface to access the business logic of each agent is managed through the Notebooks in the Jupyter Lab container.

Before you can launch the PoC, you must set the .env file for each of agent. For a quick start, copy the files `playground/<agent-name>/<agent-name>_example.env` and rename them to `playground/<agent-file>/.env`.

Then, move to the `./SyMPC` directory and clone the [SyMPC](https://github.com/OpenMined/SyMPC) repository. The SyMPC package is created by the OpenMined organization, and an extension of the [PySyft](https://github.com/OpenMined/PySyft) library, and automatically installs PySyft (which is needed for this PoC). 

Finally run:

`./manage.sh start`

This spins up all docker containers defined in the `docker-compose.yml` file and named in the DEFAULT_CONTAINERS variable defined in the `manage.sh` shell script. 

**Note:** An error when spinning the docker containers might be `Service '<docker-container>' failed to build : Build failed`. A possible solution is to up the Memory available to docker to 3GB (see [StackOverflow post](https://stackoverflow.com/questions/44533319/how-to-assign-more-memory-to-docker-container).

The ULRs for the jupyter notebook server for each agent can be retrieved by running `./scripts/get_URLS.sh` in a terminal from the root of this project.

To stop the PoC either:

`./manage.sh stop` - this terminates the containers but persists the volumes. Specifically the agent wallet storage held in postgres-db's

`./manage.sh down` - terminate containers and delete all volumes (e.g., the issued VCs stored in an agent's wallet)

## Writing Business Logic

The aim of this respository is to simplify the process by which you can spin up a set of actors specific to a domain and start to experiment with relevant information exchanges using the Hyperledger verifiable information exchange platform.

All business logic is written is python through jupyter notebooks. Alongside this repository we have developed a pip installable package the [Aries Cloud Controller](https://github.com/didx-xyz/aries-cloudcontroller-python), which provides an easy to use interface to interact with the Swagger API exposed by ACA-Py agents as well as receive and handle webhook events they post.

To streamline the process of writing business logic further, each business-logic docker service has the `recipes` folder mounted such that it is accessible through the jupyter interface. In here there are a set of templates for common protocols you might want your agents to engage in. We suggest you copy these templates into the root of the notebook server and customise from there.

If you wish to learn more about applying SSI, the Hyperledger Stack and the Aries Cloud Controller within this setting a set of tutorials have been developed within a similar notebook-playground environment in the [OpenMined PyDentity](https://github.com/OpenMined/PyDentity) repo. This code is a generalisation of a pattern we repeated regularly while building this code.

## Configuring the Playground

The playground is designed to make it easy for you to add new actors and start writing SSI ecosystem flows. 

To add an actor you need to make three changes:

* Create a folder under `playground` for that actor and make sure it has a .env file under that folder. You can copy the template `actor` folder and use the `dummy.env` file to get started but will need to edit the file.
* Define the actor services in the `docker-compose.yml`. More detailed instructions included in the comments in that file, including commented out set of services for the actor `actor` that you can copy and use as a template to get started. You will need to edit these.
* Add the new services to the DEFAULT_CONTAINERS variable in the `manage.sh` script

Feel free to customise authority and manufacturer1 aswell. It makes sense to name your actors something meaningful to the usecase you are trying to model.

## ACA-Py Agent Configuration

Each agent instance has it's own environment file e.g. `authority/.authority-example.env`. These define default ACA-PY environment variables, which are best understood by reading through the code that parses them. This can be found [here](https://github.com/hyperledger/aries-cloudagent-python/blob/main/aries_cloudagent/config/argparse.py).

## Using Different Indy Networks

An aries agent points to the indy network it wishes to use to write and resolve cryptographic objects to and from. All actors in the flow should use the same network - See the ACA_PY_GENESIS_URL argument in .env files.

The master branch currently is set to use the Sovrin StagingNet.

It is also possible to use the BC Gov's Test Network VON - http://greenlight.bcovrin.vonx.io/genesis

Or a local ledger can be spun up either within the docker-compose.yml or separately by cloning the [VON codebase](https://github.com/bcgov/von-network)

## Moving Your Ideas Out of The Playground

At some point you are likely to want to make your ideas more "real". Maybe your use case needs a frontend, or wants to be publicly accessible and automatically responsive to agents on the public internet.

There are two repositories that might help you take that next step, based on experiments we have been doing ourselves.

* Issuer Service: https://github.com/wip-abramson/aries-issuer-service 
    * This codebase lets you run an agent and associated server so that you can write logic for how the agent should respond to certain events. For example a connection becoming active might be challenged to present a specific set of attributes from a certain schema. Or it might automatically trigger the issuance of a credential. I have found this useful to get credentials out into the hands of holders so they can use them elsewhere in your system.
* Aries Full Stack React Starter: https://github.com/wip-abramson/aries-acapy-fullstack-starter
    * Want to build a full stack application with SSI capabilities. This might help you get started.
    
One of the great things I have found with this playground is you can model the entire ecosystem you are focused on, test assumptions and validate usecases. Then you can focus on a single actor and implement a POC for a more realistic version of their application/interface.

# Error Messages
There is a chance you run into certain error messages. Here is a list of how to deal with a few of them: 

### Error 1: Non-responsive agents
In some cases, the agents fail to connect with one another. If too many connection requests are made, a `402` error appears in the Docker logs of one of the agents:
```
aries_cloudagent.transport.outbound.manager ERROR >>> Error when posting to: https://682ea719f54a.ngrok.io; Error: (<class 'aries_cloudagent.transport.outbound.base.OutboundTransportError'>, OutboundTransportError('Unexpected response status 402, caused by: Payment Required',), <traceback object at 0x7fe0d157d788>); Re-queue failed message ...
```
The error asks the user to provide Payment for the ngrok service. A solution is to stop the docker containers through `./manage.sh stop` and restarting them `./manage.sh start`.

### Error 1: Proxy Settings

* See [this Medium article](https://airman604.medium.com/getting-docker-to-work-with-a-proxy-server-fadec841194e) with information on how to set up a proxy for docker-compose
* Frequent error when building the docker containers: `Service '<docker-container>' failed to build : Build failed`. Try to increase the memory available memory to 3GB (see [StackOverflow post](https://stackoverflow.com/questions/44533319/how-to-assign-more-memory-to-docker-container)
