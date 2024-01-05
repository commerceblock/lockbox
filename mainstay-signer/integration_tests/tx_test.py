from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# Bitcoin node RPC credentials
rpc_user = 'someusername'
rpc_password = 'somepassword'
rpc_host = 'localhost'
rpc_port = 8332  # Default Bitcoin RPC port

# Connect to the Bitcoin node
rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}")

try:
    # Example RPC call: get the blockchain information
    blockchain_info = rpc_connection.getblockchaininfo()
    print("Blockchain Info:")
    print("Chain:", blockchain_info['chain'])

    rpc_connection.loadwallet("wallet2")

except JSONRPCException as e:
    print(f"Error: {e}")

try:
    rpc_connection.walletpassphrase("phrase",1000000)

except JSONRPCException as e:
    print(f"Error: {e}")

try:
    addr = rpc_connection.getnewaddress()
    print("send address: "+ addr)
    info = rpc_connection.getaddressinfo(addr)
    print("  pubkey: "+info['pubkey'])
    print("  witness program: "+info['witness_program'])
    print("  scriptPubKey: "+info['scriptPubKey'])
    privkey = rpc_connection.dumpprivkey(addr)
    print("  privkey: "+ privkey)

    txid = rpc_connection.sendtoaddress(addr,0.001)
    print("")

    print("input info:")
    print("txid: "+txid)
    print("vout: 0")
    print("value: 100000")

    print("")

    addr2 = rpc_connection.getnewaddress()
    print("pay to address: "+ addr2)
    info = rpc_connection.getaddressinfo(addr2)
    print("  pubkey: "+info['pubkey'])
    print("  witness program: "+info['witness_program'])
    print("  scriptPubKey: "+info['scriptPubKey'])
    privkey2 = rpc_connection.dumpprivkey(addr2)
    print("  privkey: "+ privkey2)

    inputs = {}
    inputs["txid"] = txid
    inputs["vout"] = 0
    outputs = {}
    outputs[addr2] = 99000

    raw_tx = rpc_connection.createrawtransaction([inputs],outputs)

    print("")
    print("raw unsigned: "+raw_tx)

except JSONRPCException as e:
    print(f"Error: {e}")


