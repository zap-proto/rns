# zap-rns — Resource Name Service over ZAP.
#
# Service names are bound to KEM public keys at registration time.
# Lookup returns (name, kemPubKey, sig). Spoofing a name reduces to
# KEM key compromise + signature forgery — strictly stronger than DNS
# or service-mesh discovery. See zap-proto/papers/rns-identity-binding.

# Record is one name → key binding. ttl bounds caching; the signing
# party (the registry root) signs everything except `signature` itself.
struct Record
  name      Text
  kemPubKey Data
  sigPubKey Data
  ttl       UInt32
  notBefore UInt64    # unix nanos
  notAfter  UInt64
  registry  Text      # which RNS authority issued this
  signature Data

# Query is a name lookup. Optional `auth` carries a token signed by
# the requester's long-term key, enabling encrypted-to-RNS lookups.
struct Query
  name Text
  auth Data

# Response carries one Record matching the query, or an error
# discriminating between "not found", "expired", and "denied".
struct Response
  union
    record   Record
    notFound Text
    expired  Record
    denied   Text
