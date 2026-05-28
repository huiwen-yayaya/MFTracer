"""
Tornado Cash on-chain analysis
Demonstrates why TC is a blind spot for MFTracer (paper §5.2)

Uses two specific real transactions from Etherscan:
  Deposit  : 0x447ad473...  (block 25191712, 0.1 ETH)
  Withdraw : 0x9e42f2c9...  (block 25191576)
"""

from web3 import Web3
import warnings
warnings.filterwarnings("ignore")

RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/your_api_key"
w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "Cannot connect"
print(f"Connected. Latest block: {w3.eth.block_number}\n")

# Two real TC transactions from Etherscan (May 2026)
DEPOSIT_TX  = "0x447ad4735f74d8f7ee79b45a8c6462a39c554c6dc779f15a85eb47c6dc3283d9"
WITHDRAW_TX = "0x9e42f2c95d0a518bd4f9bd3935d44f2501bc257ddb7526fc615f1c488a7d6916"

# TC 0.1 ETH pool ABI (events only)
TC_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "name": "commitment",    "type": "bytes32"},
            {"indexed": False, "name": "leafIndex",     "type": "uint32"},
            {"indexed": False, "name": "timestamp",     "type": "uint256"},
        ],
        "name": "Deposit",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "name": "to",            "type": "address"},
            {"indexed": False, "name": "nullifierHash", "type": "bytes32"},
            {"indexed": True,  "name": "relayer",       "type": "address"},
            {"indexed": False, "name": "fee",           "type": "uint256"},
        ],
        "name": "Withdrawal",
        "type": "event",
    },
]

TC_POOL = Web3.to_checksum_address("0x12D66f87A04A9E220C9D05126360539b6c02fd7e")
contract = w3.eth.contract(address=TC_POOL, abi=TC_ABI)

# ── analyse deposit transaction ───────────────────────────────────────────────
print("=" * 60)
print("DEPOSIT TRANSACTION")
print("=" * 60)

d_tx      = w3.eth.get_transaction(DEPOSIT_TX)
d_receipt = w3.eth.get_transaction_receipt(DEPOSIT_TX)

print(f"Tx hash   : {DEPOSIT_TX}")
print(f"Block     : {d_tx['blockNumber']}")
print(f"Sender    : {d_tx['from']}  ← depositor")
print(f"Value     : {Web3.from_wei(d_tx['value'], 'ether')} ETH")
print()

# decode Deposit event from receipt logs
deposit_event = None
for log in d_receipt.logs:
    try:
        evt = contract.events.Deposit().process_log(log)
        deposit_event = evt
        break
    except Exception:
        continue

if deposit_event:
    commitment = deposit_event.args.commitment.hex()
    print(f"Commitment (on-chain record): 0x{commitment}")
    print(f"Leaf index : {deposit_event.args.leafIndex}")
    print()
    print("What TC records on-chain: ONLY the commitment hash.")
    print("The depositor address exists in the tx 'from' field,")
    print("but is NOT stored in the event log that TC emits.")
else:
    print("(Could not decode Deposit event — pool contract may differ)")

# ── analyse withdraw transaction ──────────────────────────────────────────────
print()
print("=" * 60)
print("WITHDRAWAL TRANSACTION")
print("=" * 60)

w_tx      = w3.eth.get_transaction(WITHDRAW_TX)
w_receipt = w3.eth.get_transaction_receipt(WITHDRAW_TX)

print(f"Tx hash   : {WITHDRAW_TX}")
print(f"Block     : {w_tx['blockNumber']}")
print(f"Sender    : {w_tx['from']}  ← relayer (not the recipient)")
print()

withdraw_event = None
for log in w_receipt.logs:
    try:
        evt = contract.events.Withdrawal().process_log(log)
        withdraw_event = evt
        break
    except Exception:
        continue

if withdraw_event:
    nullifier = withdraw_event.args.nullifierHash.hex()
    recipient = withdraw_event.args.to
    print(f"Recipient      : {recipient}  ← where ETH goes")
    print(f"Nullifier hash : 0x{nullifier}")
    print()
    print("What TC records on-chain: recipient address + nullifier hash.")
    print("No commitment hash. No depositor address.")
else:
    print("(Could not decode Withdrawal event)")

# ── the core comparison ───────────────────────────────────────────────────────
print()
print("=" * 60)
print("CAN WE LINK DEPOSIT → WITHDRAWAL FROM CHAIN DATA?")
print("=" * 60)

if deposit_event and withdraw_event:
    depositor   = d_tx['from']
    recipient   = withdraw_event.args.to
    commitment  = deposit_event.args.commitment.hex()
    nullifier   = withdraw_event.args.nullifierHash.hex()

    print(f"\nDepositor  : {depositor}")
    print(f"Recipient  : {recipient}")
    print(f"Same address?      {depositor.lower() == recipient.lower()}")
    print()
    print(f"Commitment : 0x{commitment}")
    print(f"Nullifier  : 0x{nullifier}")
    print(f"Same value?        {commitment == nullifier}")
    print()
    print("Result: no shared field between the deposit and withdrawal events.")
    print("Chain data alone cannot link them.")

# ── what MFTracer sees ────────────────────────────────────────────────────────
print()
print("=" * 60)
print("WHAT MFTRACER SEES  (paper §5.2)")
print("=" * 60)
print(f"""
Normal transfer A → B:
  Transfer event: from=A, to=B, value=X
  MFTracer reads this directly via Algorithm 1 (§3.2)

Tornado Cash deposit ({d_tx['from'][:10]}...):
  No Transfer event emitted
  Only: Deposit(commitment=0x{commitment[:16]}...)
  MFTracer sees: funds enter TC pool, flow STOPS here

Tornado Cash withdrawal (→ {withdraw_event.args.to if withdraw_event else '?'}):
  Only: Withdrawal(to=recipient, nullifierHash=0x{nullifier[:16] if withdraw_event else '?'}...)
  MFTracer sees: a new unlinked outflow from TC pool

The mathematical link (commitment ↔ nullifier) lives inside
the zero-knowledge proof only — unreadable from chain data.
This is exactly the blind spot described in §5.2.
""")