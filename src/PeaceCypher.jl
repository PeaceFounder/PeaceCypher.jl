module PeaceCypher

using Random
using CryptoGroups
using CryptoSignatures
using DiffieHellman
using SecureIO
using Nettle
using Pkg.TOML

struct Notary
    G::AbstractGroup
end

const Key = CryptoSignatures.Signer

struct Signer
    key::Key
    notary::Notary
end

# This should allow to improve notation in the future if necessary
struct Signature
    sig::Dict
    notary::Notary
end

Base.Dict(s::Signature) = s.sig

function binary(s::Signature)
    io = IOBuffer()
    TOML.print(io,Dict(s))
    return take!(io)
end

function Signature(binary::Vector{UInt8}, notary::Notary)  
    dict = TOML.parse(String(copy(binary)))
    return Signature(dict, notary)
end


Notary() = Notary(CryptoGroups.Scep256k1Group())

hash(x::AbstractString, crypto::Notary) = BigInt(Base.hash(x))
hash(x, crypto::Notary) = hash(string(x), crypto)


newsigner(crypto::Notary) = Signer(Key(crypto.G),crypto)

function sign(value, notary::Notary, signer::Key)
    signature = DSASignature(hash(value, notary), signer)
    signaturedict = Dict(signature) 
    return Signature(signaturedict, notary)
end

### Perhaps I could use certify
sign(value, signer::Signer) = sign(value, signer.notary, signer.key)

function verify(value, signature::Dict, crypto::Notary)
    signature = DSASignature{BigInt}(signature)
    return CryptoSignatures.verify(signature,crypto.G) && signature.hash==hash(value, crypto)    
end

verify(value, s::Signature) = verify(value, s.sig, s.notary)

id(s::Dict, crypto::Notary) = hash(string(parse(BigInt,s["pub"],base=16)), crypto) 
id(s::Signature) = id(s.sig, s.notary)
id(s::Signer) = hash("$(s.key.pubkey)", s.notary)


struct CypherSuite
    notary::Notary
end


function fold(value::BigInt, signature::Dict)
    dict = Dict("value"=>string(value, base=16),"signature"=>signature)
    io = IOBuffer()
    TOML.print(io,dict)
    return take!(io)
end

function unfold(envelope::Vector{UInt8})
    dict = TOML.parse(String(copy(envelope)))
    value = parse(BigInt,dict["value"], base=16)
    signature = dict["signature"]
    return value, signature
end


function seal(value::BigInt, signer::Signer)
    signature = sign(value, signer)
    return fold(value, Dict(signature))
end

function unseal(envelope::Vector{UInt8}, crypto::Notary)
    value, sdict = unfold(envelope)
    signature = Signature(sdict, crypto)

    if verify(value, signature) ### The id is of ID type thus there shall be no problem
        return value, id(signature)
    else
        return value, nothing
    end
end

function seal(value::BigInt)
    str = string(value, base=16)
    return Vector{UInt8}(str)
end

function unseal(envelope::Vector{UInt8})
    value = parse(BigInt,String(copy(envelope)),base=16)
    return value, nothing
end


function rngint(len::Integer)
    max_n = ( BigInt(1) << len ) - 1
    if len > 2
        min_n = BigInt(1) << (len - 1)
        return rand(min_n:max_n)
    end
    return rand(1:max_n)
end

# Where did I need this hack?
import Base.in
in(x::Nothing,y::Nothing) = true


function secure(socket::IO, crypto::CypherSuite, signer::Signer, id)
    G = crypto.notary.G

    dh = DH(value->seal(value,signer),envelope->unseal(envelope,crypto.notary),G,(x,y,z)->seal(hash("$x $y $z",crypto.notary)),() -> rngint(100))

    key, idr = diffiehellman(socket, dh)
    @assert idr in id "$idr not in $id"
    securesocket = SecureSocket(socket, key)
    return securesocket
end

function secure(socket::IO, crypto::CypherSuite, signer::Signer)
    G = crypto.notary.G
    
    dh = DH(value->seal(value,signer),envelope->unseal(envelope),G,(x,y,z)->seal(hash("$x $y $z",crypto.notary)),() -> rngint(100))

    key, idr = diffiehellman(socket, dh)
    securesocket = SecureSocket(socket, key)
    return securesocket
end


function secure(socket::IO, crypto::CypherSuite, id)
    G = crypto.notary.G

    dh = DH(value->seal(value),envelope->unseal(envelope,crypto.notary),G,(x,y,z)->seal(hash("$x $y $z",crypto.notary)),() -> rngint(100))

    key, idr = diffiehellman(socket, dh)
    @assert idr in id "$idr not in $id"
    securesocket = SecureSocket(socket, key)
    return securesocket
end

export Notary, hash, verify, newsigner, id
export Signer, sign
export Signature, binary, verify, id # Dict
export CypherSuite, secure

end # module
