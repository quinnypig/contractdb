# ContractDB

ContractDB is an authoritative DNS server backed by DynamoDB. It is the inverse of [AWS Labs' ExtendDB](https://github.com/aws-samples/extenddb): instead of putting a DynamoDB API in front of other databases, it puts a DNS interface in front of a DynamoDB table.

Yes, it is a real DNS server. That's not a bug.

> [!WARNING]
> This is an experimental project, not a recommendation to expose a database to the public Internet. The default read policy is open. Use network controls and TSIG authentication around real data.

## How it works

The table must have a string partition key (the default attribute name is `pk`). A point lookup maps the labels below the configured zone back to that key:

```text
user.alice.contractdb.internal.  TXT  ->  GetItem(pk="user.alice")
```

```console
$ dig @127.0.0.1 -p 1053 +short user.alice.contractdb.internal TXT
"{\"email\":\"alice@example.com\",\"limits\":{\"dataTransferBudgetTb\":42,\"riCoverage\":100},\"pk\":\"user.alice\",\"plan\":\"enterprise\"}"
```

The complete item is JSON in one TXT record. Values larger than 255 bytes use multiple character strings inside that record, preserving their order. A missing item returns NXDOMAIN with the zone SOA in the authority section.

| Query | Result |
|---|---|
| `<zone>` SOA / NS | Zone metadata |
| `_contractdb.<zone>` TXT | Service version and table |
| `_contractdb.health.<zone>` TXT | Health response (`UP`) |
| `_contractdb.metrics.<zone>` TXT | In-process counters as JSON |
| `ns1.<zone>` A / AAAA | Configured authoritative-server address |
| `<key>.<zone>` TXT | Item lookup by partition key |
| `k-<base32>.<zone>` TXT | Lookup for a case-sensitive or DNS-unsafe key |
| `<value>.<index>.<zone>` TXT | Query a configured DynamoDB GSI |
| `<zone>` AXFR / IXFR | TSIG-authenticated zone transfer |

DNS names are case-insensitive. Use the unpadded, lower-case `k-<base32>` form for keys containing uppercase letters, spaces, symbols, or other data that DNS cannot safely round-trip.

## Run it

Go 1.27 or newer is required.

```sh
go build -o contractdb .

# No AWS account required: serve the built-in sample data.
./contractdb serve -demo -addr 127.0.0.1:1053

# Or use a real table and the standard AWS credential chain.
CONTRACTDB_TABLE=contracts ./contractdb serve \
  -addr :53 \
  -zone contractdb.internal.
```

`contractdb init` writes a documented `contractdb.toml`; `serve`, `status`, `stop`, and `healthcheck` read that file by default. Flags take precedence over environment variables, which take precedence over the file.

Common environment variables are `CONTRACTDB_ADDR`, `CONTRACTDB_ZONE`, `CONTRACTDB_TABLE`, `CONTRACTDB_PK`, `CONTRACTDB_TTL`, `CONTRACTDB_ENDPOINT`, `CONTRACTDB_ADVERTISE_IP`, `CONTRACTDB_CONSISTENT`, `CONTRACTDB_DEMO`, `CONTRACTDB_AUTH`, `CONTRACTDB_TSIG_KEYS`, `CONTRACTDB_DOH`, `CONTRACTDB_TLS_CERT`, and `CONTRACTDB_TLS_KEY`.

Point reads use `GetItem`. GSI lookups use `Query`, transfers use `Scan`, and dynamic updates use `PutItem` or `DeleteItem`, so grant only the DynamoDB permissions you enable.

## UDP truncation

Classic DNS over UDP allows 512-byte responses unless the client advertises a larger EDNS0 buffer. ContractDB sets the TC bit when the response does not fit, allowing a normal resolver to retry over TCP. TCP responses carry the complete JSON value.

```console
$ dig @127.0.0.1 -p 1053 contract.nda-001.contractdb.internal TXT +noedns +ignore +comments
;; flags: qr aa tc rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

$ dig @127.0.0.1 -p 1053 contract.nda-001.contractdb.internal TXT +noedns +tcp +short
"{...complete JSON split into ordered TXT character strings...}"
```

## Authentication and updates

RFC 2136 UPDATEs and AXFR/IXFR transfers always require a valid TSIG signature. Ordinary reads are open unless `auth.mode = "tsig-required"` or `-auth tsig-required` is set.

The server's TSIG key file contains one key per line:

```text
# name                   base64 secret
contractdb-key.          c3VwZXItc2VjcmV0LXJlcGxhY2UtbWU=
```

```sh
./contractdb serve -demo -addr 127.0.0.1:1053 \
  -tsig-keys ./tsig.keys \
  -auth tsig-required
```

An UPDATE inserts or replaces an item with an IN/TXT record and deletes it with the standard `RemoveName` or TXT-RRset deletion form. The TXT payload must be a JSON object. To preserve RFC 2136 atomicity over the storage interface, one UPDATE packet may affect only one owner name. Successful writes advance the SOA serial, enter the in-memory IXFR journal, and send NOTIFY to configured secondaries.

## Optional protocol features

- Configure `dynamodb.gsis` (or `-gsi index=attribute`) to expose equality queries on selected string-key GSIs.
- Set `doh.listen` (or `-doh`) to enable DNS over HTTPS. ContractDB generates a localhost self-signed certificate when no certificate and key are provided. DoH is read-only and is refused when `tsig-required` mode is active.
- Enable `dnssec.enabled` (or pass `-dnssec-dir`) for experimental online ECDSA P-256 signing. Persist the key and publish the corresponding DS record if you expect validation across restarts.
- Configure `notify.notifiees` (or `-notify`) to send RFC 1996 NOTIFY after writes.

## Important limitations

- DynamoDB items are represented as JSON, so DynamoDB binary/set type distinctions are not fully reversible through UPDATE payloads.
- The IXFR journal is in memory and holds at most 4,096 changes. Older clients receive a full transfer.
- GSI and transfer operations can consume substantial DynamoDB capacity.
- TTL defaults to five seconds, but resolvers can still cache reads and negative answers.
- DoH does not accept UPDATE or zone-transfer operations.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

The tests cover point queries, DNS truncation, wire-encoded updates, TSIG policy, RFC 2136 prerequisites, AXFR/IXFR sequencing, NOTIFY, DNSSEC signing, DoH, and DynamoDB value conversion.
