# https://proofivy.com
# Includes code from:
# https://github.com/thunderstore-io/ipfs-cid

import requests
from hashlib import sha256
from base64 import b32encode
import web3
import json
from gnosis.safe.safe_tx import SafeTx
from gnosis.safe.safe import Safe
from gnosis.eth.ethereum_client import EthereumClient
import os

WEB3_RPC_ENDPOINT = os.environ['WEB3_RPC_ENDPOINT']
PROOFIVY_ADDRESS = os.environ['PROOFIVY_ADDRESS']
GNOSIS_ADDRESS = os.environ['GNOSIS_ADDRESS']
GNOSIS_SIGNER_PRIVATE_KEY = os.environ['GNOSIS_SIGNER_PRIVATE_KEY']
GNOSIS_SIGNER_ADDRESS = os.environ['GNOSIS_SIGNER_ADDRESS']
CHAIN_ID = os.environ['CHAIN_ID']
GNOSIS_CHAIN_PREFIX = os.environ['GNOSIS_CHAIN_PREFIX']
ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'

safe_version = os.environ['safe_version']
guild = os.environ['guild']
vyper_release_version = os.environ['vyper_release_version']
vyper_download_url = os.environ['vyper_download_url']
gnosis_api_url = os.environ['gnosis_api_url']
gnosis_api_url_vyper = gnosis_api_url.format(safe_address=GNOSIS_ADDRESS)

MULTICODEC_CIDV1 = b"\x01"
MULTICODEC_RAW_BINARY = b"\x55"
MULTICODEC_SHA_2_256 = b"\x12"
MULTICODEC_BLAKE3 = b"\x1e"
MULTICODEC_LENGTH_256 = b"\x20"
PREFIX = "b"


CID_PREFIX_SHA256 = b"".join(
    [
        MULTICODEC_CIDV1,
        MULTICODEC_RAW_BINARY,
        MULTICODEC_SHA_2_256,
        MULTICODEC_LENGTH_256,
    ],
)

proofivy_abi_json = """[
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": false,
          "name": "hash",
          "type": "string"
        },
        {
          "indexed": false,
          "name": "commit_count",
          "type": "uint256"
        }
      ],
      "name": "PublicCommit",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": false,
          "name": "message",
          "type": "string"
        },
        {
          "indexed": false,
          "name": "public_message_count",
          "type": "uint256"
        }
      ],
      "name": "PublicMessage",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "name": "guild",
          "type": "string"
        }
      ],
      "name": "GuildFounded",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "name": "guild",
          "type": "string"
        },
        {
          "indexed": true,
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": false,
          "name": "hash",
          "type": "string"
        },
        {
          "indexed": false,
          "name": "guild_commit_count",
          "type": "uint256"
        }
      ],
      "name": "GuildMemberCommit",
      "type": "event"
    },
    {
      "anonymous": false,
      "inputs": [
        {
          "indexed": false,
          "name": "guild",
          "type": "string"
        },
        {
          "indexed": true,
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": false,
          "name": "message",
          "type": "string"
        },
        {
          "indexed": false,
          "name": "guild_message_count",
          "type": "uint256"
        }
      ],
      "name": "GuildMemberMessage",
      "type": "event"
    },
    {
      "inputs": [],
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "name": "_contract_owner",
          "type": "address"
        }
      ],
      "name": "change_owner",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "_commit_price",
          "type": "uint256"
        }
      ],
      "name": "set_public_commit_price",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "_message_price",
          "type": "uint256"
        }
      ],
      "name": "set_public_message_price",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "hash",
          "type": "string"
        }
      ],
      "name": "public_commit",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function",
      "payable": true
    },
    {
      "inputs": [
        {
          "name": "message",
          "type": "string"
        }
      ],
      "name": "public_message",
      "outputs": [],
      "stateMutability": "payable",
      "type": "function",
      "payable": true
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "first_admin",
          "type": "address"
        }
      ],
      "name": "found_guild",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "admin",
          "type": "address"
        }
      ],
      "name": "add_admin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "admin",
          "type": "address"
        }
      ],
      "name": "remove_admin",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        }
      ],
      "name": "aspire_membership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        }
      ],
      "name": "remove_aspiring_membership",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "member",
          "type": "address"
        }
      ],
      "name": "add_member",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "member",
          "type": "address"
        }
      ],
      "name": "remove_member",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "hash",
          "type": "string"
        }
      ],
      "name": "guild_commit",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "name": "guild",
          "type": "string"
        },
        {
          "name": "message",
          "type": "string"
        }
      ],
      "name": "guild_message",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "public_commit_price",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [],
      "name": "public_message_price",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [],
      "name": "public_commit_counter",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "uint256"
        }
      ],
      "name": "public_commit_senders",
      "outputs": [
        {
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "uint256"
        }
      ],
      "name": "public_commits",
      "outputs": [
        {
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [],
      "name": "public_message_counter",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "uint256"
        }
      ],
      "name": "public_message_senders",
      "outputs": [
        {
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "uint256"
        }
      ],
      "name": "public_messages",
      "outputs": [
        {
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        }
      ],
      "name": "guilds",
      "outputs": [
        {
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "address"
        }
      ],
      "name": "guild_admins",
      "outputs": [
        {
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "address"
        }
      ],
      "name": "guild_aspiring_members",
      "outputs": [
        {
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "address"
        }
      ],
      "name": "guild_members",
      "outputs": [
        {
          "name": "",
          "type": "bool"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        }
      ],
      "name": "guild_commit_counter",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "uint256"
        }
      ],
      "name": "guild_commit_senders",
      "outputs": [
        {
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "uint256"
        }
      ],
      "name": "guild_commits",
      "outputs": [
        {
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        }
      ],
      "name": "guild_message_counter",
      "outputs": [
        {
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "uint256"
        }
      ],
      "name": "guild_message_senders",
      "outputs": [
        {
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    },
    {
      "inputs": [
        {
          "name": "arg0",
          "type": "string"
        },
        {
          "name": "arg1",
          "type": "uint256"
        }
      ],
      "name": "guild_messages",
      "outputs": [
        {
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": true
    }
]"""


def encode_b32(data: bytes) -> str:
    b32 = b32encode(data).decode()
    return PREFIX + b32.lower().replace('=', '')


# Get latest release and calculate hash
download_url = vyper_download_url.format(version=vyper_release_version)
response = requests.get(download_url)
response_data = response.content
sha256_file = sha256(response_data).digest()
hash_string = encode_b32(CID_PREFIX_SHA256 + sha256_file)
# Create Proofivy transaction
w3 = web3.Web3(web3.HTTPProvider(WEB3_RPC_ENDPOINT))
proofivy_abi = json.loads(proofivy_abi_json)
proofivy_contract = w3.eth.contract(address=PROOFIVY_ADDRESS, abi=proofivy_abi)
txn_dict = proofivy_contract.functions.guild_commit(guild, hash_string
                                                    ).build_transaction({'chainId': CHAIN_ID, 'gas': 0, 'nonce': 0})
# Create Gnosis Safe transaction
safe_eth_client = EthereumClient(WEB3_RPC_ENDPOINT)
safe = Safe(GNOSIS_ADDRESS, safe_eth_client)
safe_info = safe.retrieve_all_info()
safe_tx = SafeTx(safe_eth_client,
                 to=PROOFIVY_ADDRESS,
                 data=txn_dict['data'],
                 safe_address=GNOSIS_ADDRESS,
                 operation=0,
                 value=0, safe_tx_gas=0, base_gas=0, gas_price=0,
                 gas_token=ZERO_ADDRESS,
                 refund_receiver=ZERO_ADDRESS, safe_nonce=safe_info.nonce,
                 safe_version=safe_version, chain_id=CHAIN_ID)

send_dict = {
  'safe': GNOSIS_CHAIN_PREFIX + GNOSIS_ADDRESS,
  'to': PROOFIVY_ADDRESS,
  'value': 0,
  'data': txn_dict['data'],
  'operation': 0,
  'safeTxGas': 0,
  'baseGas': 0,
  'gasPrice': 0,
  'nonce': safe_info.nonce,
  'contractTransactionHash': safe_tx.safe_tx_hash.hex(),
  'sender': GNOSIS_SIGNER_ADDRESS,
  'signature': '0x' + safe_tx.sign(GNOSIS_SIGNER_PRIVATE_KEY).hex()
}
# Send transaction
print(send_dict)

# gnosis_api_response = requests.post(gnosis_api_url_vyper, json=send_dict)
# print(gnosis_api_response)
