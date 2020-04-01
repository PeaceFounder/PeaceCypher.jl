using PeaceCypher
using PeaceVote.DemeNet.Plugins: uuid
using PeaceVote.DemeNet: CypherSuite, Notary

cypher = uuid(:PeaceCypher)

notary = Notary(CypherSuite(cypher),:default)

signer = notary.Signer()

msg = "Hello World"
signature = notary.Signature(msg,signer)
@show notary.verify(msg,signature)

cypher = Cypher(CypherSuite(cypher),:default)

@show cypher.G
@show cypher.rng()

io = IOBuffer()
secureio = cypher.secureio(io,24235235)
write(secureio,b"hello")
take!(io)

@show notary.Signature(Dict(signature)) == signature
@show notary.Signer(Dict(signer)) == signer

