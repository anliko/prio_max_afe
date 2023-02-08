from random import randint

# In the following we implement the maximum AFE that is represented in the paper of Corrigan-Gibbs and
# Boneh from 2017.
# Their work is called "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
# and describes how to realize privacy-preserving aggregation of distributed, sensitive user data
# using their protocol "Prio".
# Details of the execution are described in that paper.
# For computing the maximum we need the and-AFE and the max-AFE:

# Set the upper border for all secrets (each secret data must be in [0,b-1])
b = 100

# Set the length of the and-encoding (computation succeeds with probability 1-2**(-lam))
lam = 50


# At first the client computes the encoding of the max AFE.
# For this the first secret bits are set to 1 and the rest is set to 0.
# param secret: the secret data of the client e.g. a number of downloaded bytes, must be in [0,b)
def encode_max_afe(secret: int):
    # Handle case that the secret is out of range
    if secret >= b:
        print("The secret must be inside [0,", b - 1, "]!")
        return
    secret_unary = list()
    for i in range(0, b):
        if secret <= i:
            secret_unary.append(1)
        else:
            secret_unary.append(0)
    #    print("Result of encode_max_afe on input ",secret,": ",secret_unary)
    return secret_unary


# In the next step, the unary secret is encoded using the AFE for and aggregations.
# For this, each 1 is replaced by lam many 0s and each 0 is replaced by a random bitstring of length lam
# param secret_unary: the secret of the client after encoding it with encode_max_afe()
def encode_and_afe(secret_unary: list):
    encoding = list()
    for elem in secret_unary:
        if elem == 1:
            encoding.append([0 for _ in range(0, lam)])
        else:
            encoding.append([randint(0, 1) for _ in range(0, lam)])
    #    print("Result of encode_and_afe on input",secret_unary,": ",encoding)
    return encoding


# After that, the client splits his encoded secret into shares using the xor function.
# It creates one share for each server. In this case we use 2 servers, which is the least needed amount.
# param encoding: the secret of the client after applying both encode algorithms
def create_shares(encoding: list):
    # All but one shares are chosen uniformly at random:
    share1 = [[randint(0, 1) for _ in range(0, lam)] for _ in range(0, b)]
    # And the last share is computed with xor (if shares are binary as here)
    share2 = list()
    for i in range(0, b):
        temp_list = list()
        for j in range(0, lam):
            temp_list.append(encoding[i][j] + share1[i][j] % 2)  # xor function
        share2.append(temp_list.copy())
    #    print("First share of",encoding,": ",share1)
    #    print("Second share of",encoding,": ",share2)
    return share1, share2


# Then each server s gets the shares share_s that were create for it.
# Thus, server1 gets all share1 and server2 gets all share2.
# In the original they validate those shares, but for maximum aggregation arbitrary binaries are allowed
# and here all shares are binary per construction.
# All (correctly encoded) shares are aggregated using xor.
# param all_shares: contains all shares that are meant for the specific server
def server_agg(all_shares: list):
    # Aggregate all correctly encoded shares with
    server_aggregate = [[0 for _ in range(0, lam)] for _ in range(0, b)]
    for i in range(0, len(all_shares)):
        for j in range(0, b):
            for k in range(0, lam):
                if server_aggregate[j][k] == all_shares[i][j][k]:  # (alternative) xor function
                    server_aggregate[j][k] = 0
                else:
                    server_aggregate[j][k] = 1
    #    print("Result of server_agg on input",all_shares,": ",server_aggregate)
    return server_aggregate


# At last the results of all (both) servers are aggregated using again xor.
# param server_aggregates: list of results of all servers' executions of server_agg()
def final_agg(server_aggregates: list):
    # We use 2 servers here:
    servers = 2
    final_aggregate = [[0 for _ in range(0, lam)] for _ in range(0, b)]
    for i in range(0, servers):
        for j in range(0, b):
            for k in range(0, lam):
                if final_aggregate[j][k] == server_aggregates[i][j][k]:
                    final_aggregate[j][k] = 0
                else:
                    final_aggregate[j][k] = 1
    #    print("Result of final_agg on input",server_aggregates,": ",final_aggregate)
    return final_aggregate


# On input the final aggregate, one of the servers executes first the decode-algorithm of the and-AFE.
# Maps each binary that contains only 0s back to 1 and all others to 0.
# param final_aggregate: the result of final_agg, contains the xor-aggregate of the encoded secrets.
def decode_and_afe(final_aggregate: list):
    decoded_aggregate = list()
    for i in range(0, b):
        if 1 in final_aggregate[i]:
            decoded_aggregate.append(0)
        else:
            decoded_aggregate.append(1)
    #    print("Final aggregate after first decoding with decode_and_afe: ",decoded_aggregate)
    return decoded_aggregate


# At last a final decoding is needed to get the result of the maximum aggregation.
# This time we need the decode-algorithm that belongs to the maximum aggregate.
# It picks (from left to right, from index 0 to index b-1) the first 1 and outputs it as it is
# the maximum of all clients' secrets.
# param decoded_aggregate: result of decode_and_afe(), is a single list of 0..1
def decode_max_afe(decoded_aggregate: list):
    for i in range(0, b, 1):
        if decoded_aggregate[i] == 1:
            #           print("Maximum of all client-provided secrets: ",i)
            return i


# Code that is executed by the clients
def client(secret: int):
    return create_shares(
        encode_and_afe(
            encode_max_afe(secret)))


# Code that is executed by the servers
def server(share: list):
    return server_agg(share)


# One of the servers (e.g. the leader) computes the final aggregate and decodes the result
def leader_server(shares_server1, shares_server2):
    return decode_max_afe(
        decode_and_afe(
            final_agg([server(shares_server1), server(shares_server2)])))


# Runs the clients, the servers, and the leader server.
# param secrets: list of all clients' secrets. They should only be known to the clients, but as we
# run the clients those are needed as input
def run_max_afe(secrets: list):
    shares_server1 = list()
    shares_server2 = list()
    for secret in secrets:
        (share1, share2) = client(secret)
        shares_server1.append(share1)
        shares_server2.append(share2)
    maximum = leader_server(shares_server1, shares_server2)
    return maximum


# prints the result of run_max_afe()
# Change the secrets in the list to see the impact.
# But beware that they must always be < b.
print(run_max_afe([1, 15, 60, 95, 42, 99, 23]))
