using PeaceCypher
using PeaceVote

uuid = PeaceVote.uuid(:PeaceCypher)

notary = Notary(CypherSuite(uuid),:default)

signer = notary.Signer()

msg = "Hello World"
signature = notary.Signature(msg,signer)
@show notary.verify(msg,signature)

cypher = Cypher(CypherSuite(uuid),:default)

@show cypher.G
@show cypher.rng()

io = IOBuffer()
secureio = cypher.secureio(io,24235235)
write(secureio,b"hello")
take!(io)

@show notary.Signature(Dict(signature)) == signature
@show notary.Signer(Dict(signer)) == signer

