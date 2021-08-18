# Configuration of ACA-PY Agents

Ports and environment details must be determined in every agent's `agents/<agent-name>/.env` file, and matched accordingly in the `docker-compose.yml` file.

---
## Configurable variables

### 1. Adjust `agents/<agent-name>/.env` files for every agent
Each agent contains a `.env` file that determines ports for the agents. 

#### 1.1 Set indentically for all `.env` files
```
HTTP_PORT=<HTTP_PORT>
WEBHOOK_PORT=<WEBHOOK_PORT>
ADMIN_PORT=<ADMIN_PORT>
```

#### 1.2 Defind individual settings
```
# postgres DB setup (for hosting wallet and local set up)
WALLET_DB_HOST=<agent-name>-wallet-db
POSTGRES_DB=<agent-name>_wallet

# for aca-py agent
ADMIN_URL=http://<agent-name>-agent:<ADMIN_PORT>

# Used if run ./manage.sh in production
ACAPY_ENDPOINT=http://0.0.0.0:<HTTP_PORT_LOCAL>
ACAPY_WEBHOOK_URL=http://<agent-name>-jupyter:<WEBHOOK_PORT>
ACAPY_ADMIN_API_KEY=adminApiKey
ACAPY_LABEL=<agent-name>
ACAPY_WALLET_NAME=<agent-name>_Name
ACAPY_WALLET_KEY=<agent-name>_key
ACAPY_WALLET_STORAGE_CONFIG={"url":"<agent-name>-wallet-db:5432","wallet_scheme":"MultiWalletSingleTable"}
NGROK_NAME=ngrok-<agent-name>
```

### 2. Adjust `docker-compose.yml` file 

#### 2.1 Name containers
The `docker-compose.yml` file sets up four containers per agent

* `<agent-name>-wallet-db`: Container based on the `postgres:11` image to initiate a postgres database where agent data is stored. If you run `./manage stop`, the data is kept. If `./manage down`, the data is kept. 
* `ngrok-<agent-name>`: Container based on the `wernight/ngrok` image to expose agent to the public (if needed)
* `<agent-name>-agent`: ACA-PY instance of agent. Initiated from the `dockerfiles/Dockerfile.agent` file.
* `<agent-name>-jupyter`: Creates notebooks to interact with agents. Initiated from the `dockerfiles/Dockerfile.controller`, and includes the pip package *aries-cloudcontroller* and compiles the *sympc* package.

#### 2.2 Adjust information of containers
Besides the names of the containers and images, following variables must be adjusted in the individual containers: 
```
# ngrok-<agent-name>
command: ngrok http <agent-name>-agent:<HTTP_PORT> --log stdout

# <agent-name>-agent
ports:
    - <HTTP_PORT_LOCAL>:<HTTP_PORT>
    - <ADMIN_PORT_LOCAL>:<ADMIN_PORT>
    
# <agent-name>-jupyter
ports:
    - <JUPYTER_PORT_LOCAL>:<JUPYTER_PORT>
    - <WEBHOOK_PORT_LOCAL>:<WEBHOOK_PORT>
```

#### 2.3 Add networks

Add `<agent-name>-domain` to the `networks:` part at the end ofd the `docker-compose.yml` file.

### 3. Add docker containers to `.manage.sh` file

Lastly, add the four docker containers to the `DEFAULT_CONTAINERS` variable in the `.manage.sh` file

---
## Default settings in this project
Whereby the variables are set and reserved as follows:

```
# For all agents in .env and docker-compose.yml files
HTTP_PORT=3020
WEBHOOK_PORT=3010
ADMIN_PORT=3021
JUPYTER_PORT=8888
```

| Agent | `HTTP_PORT_LOCAL` | `ADMIN_PORT_LOCAL` | `JUPYTER_PORT_LOCAL` | `WEBHOOK_PORT_LOCAL` |
| --- | --- | --- | --- | --- |
| Authority | 3020 | 3021 | 8888 | 3010 |
| City | 3022 |3023  | 8890 | 3011 |
| Manufacturer1 | 4020 | 4021 | 8889 | 4010 |
| Manufacturer2 | 4022 | 4023 | 8891 | 4011 |
| Manufacturer3 | 4024 | 4025 | 8892 | 4012 |