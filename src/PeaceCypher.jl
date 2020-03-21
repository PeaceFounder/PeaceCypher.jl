module PeaceCypher

### This is a place of cryptographic definitions for Notary and Cypher. 
using PeaceVote: CypherSuite
import PeaceVote: Notary, Cypher, ID

using Random
using CryptoGroups
using CryptoSignatures
using SecureIO
using Nettle


ThisCypherSuite = CypherSuite(@__MODULE__)


function rngint(len::Integer)
    max_n = ( BigInt(1) << len ) - 1
    if len > 2
        min_n = BigInt(1) << (len - 1)
        return rand(min_n:max_n)
    end
    return rand(1:max_n)
end


function Notary(::Type{ThisCypherSuite},config::Symbol)

    G = CryptoGroups.Scep256k1Group()
    hash(x::AbstractString) = parse(BigInt,Nettle.hexdigest("sha256",x),base=16)

    Signer() = CryptoSignatures.Signer(G)
    Signer(x::Dict) = CryptoSignatures.Signer{BigInt}(x,G)
    Signature(x::Dict) = CryptoSignatures.DSASignature{BigInt}(x)
    Signature(x::AbstractString,signer) = CryptoSignatures.DSASignature(hash(x),signer)
    verify(data,signature) = CryptoSignatures.verify(signature,G) && hash(data)==signature.hash ? ID(hash("$(signature.pubkey)")) : nothing

    return Notary(Signer,Signature,verify,hash)
end

function Cypher(::Type{ThisCypherSuite},config::Symbol)
    G = CryptoGroups.Scep256k1Group()
    rng() = rngint(100)
    secureio(socket,key) = SecureSocket(socket,key)

    return Cypher(G,rng,secureio)
end

export Notary, Cypher

end # module
