using Sockets

import PeaceCypher: sign
using PeaceCypher

### Testing Notary

notary = Notary()
signer = newsigner(notary)

value = 19
signature = sign(value, signer)

@show verify(value, signature)
@show id(signer)==id(signature)

### Testing CypherSuite

crypto = CypherSuite(notary)

master = newsigner(crypto.notary)
masterid = id(master)

port = 2019

server = listen(port)

@sync begin
    @async begin 
        masters = accept(server)
        masterss = secure(masters, crypto, master)
    end
    sleep(1.)
    slave = connect(port)
    @show slavess = secure(slave, crypto, masterid)
end

