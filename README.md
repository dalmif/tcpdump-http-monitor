# HTTP Monitor

A realtime HTTP/HTTPS traffic dashboard in your browser. The backend is a single Go binary with the React UI embedded. Everything is kept in memory; there is no database.

<img width="2061" height="1284" alt="Screenshot From 2026-11-15 03-51-13" src="https://github.com/user-attachments/assets/09d73894-0f39-408f-9d77-28da789ffddc" />


It captures traffic in two ways, and both show up in the same live view:

| Source | How | What you see |
|---|---|---|
| **Gateway capture** | Runs `tcpdump` on a remote Linux box (your router, a single-board computer acting as gateway, a server…) over SSH and streams the packets back. Nothing is installed on the remote side. | Every **plain HTTP** request and response passing through that box, with headers and bodies (gzip/br/zstd/deflate decoded). **HTTPS** connections show as 🔒 rows with SNI hostname, TLS version, ALPN and byte counts. |
| **MITM proxy** (`:8080`) | Point a device's HTTP proxy at this computer and trust the CA. | Fully **decrypted HTTPS** (HTTP/1.1, HTTP/2, WebSockets), the way Proxyman or Charles show it. |

> A CA can only decrypt traffic that goes **through the proxy**. Passively captured TLS uses ephemeral (forward-secret) keys, so it can't be decrypted afterwards, even with a certificate's private key.

## Build & run

Requires Go 1.27+ and Node.js.

```sh
make                                   # builds web/ and bin/httpmonitor
./bin/httpmonitor -ssh gateway -capture -open
```

Then open http://127.0.0.1:8899. `gateway` is an SSH destination: a host alias from `~/.ssh/config`, or `user@host`.

### Remote capture requirements

The SSH login must be allowed to run `tcpdump` without a password prompt, for example as root, as a member of a capture group, or after `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`. The default remote command is:

```
tcpdump -U -s0 -w - {qfilter}
```

`{qfilter}` is the shell-quoted BPF filter and `{filter}` is the raw one. Add `-i <iface>` to pick an interface.

**Restricted capture account (recommended).** You can give the capture a dedicated key that can only run tcpdump. In the remote `~/.ssh/authorized_keys`:

```
command="tcpdump -i <iface> -U -s0 -w - $SSH_ORIGINAL_COMMAND",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA…
```

Then use `-remote-cmd '{filter}'`, so that only the filter is sent.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-ui` | `127.0.0.1:8899` | Dashboard address |
| `-proxy` | `:8080` | Proxy listen address (`""` disables it) |
| `-ssh` | *(none)* | SSH destination to capture from |
| `-remote-cmd` | `tcpdump -U -s0 -w - {qfilter}` | Command run over SSH |
| `-filter` | `tcp` | Default BPF filter |
| `-capture` | off | Start the capture on launch (or use the button) |
| `-ca-dir` | `~/.config/httpmonitor` | `ca.pem` / `ca-key.pem`, generated if missing |
| `-max-flows` | 20000 | In-memory ring size |
| `-open` | off | Open the dashboard in a browser |

### Config file

Defaults can be stored in `~/.config/httpmonitor/config.json` (or the path in `$HTTPMONITOR_CONFIG`). Flags override it.

```json
{
  "ssh": "gateway",
  "remoteCmd": "{filter}",
  "filter": "tcp",
  "capture": true,
  "proxy": ":8080"
}
```

You can also change capture and proxy settings at runtime under **⚙ Setup**.

## Features

- Live flow list (virtualized, so it stays fast with tens of thousands of rows) with a sidebar of sources, devices and domains.
- Filter: free text plus `host:` `method:` `status:4xx` `status:>=500` `client:` `path:` `type:` `source:` `kind:`, and `-token` to negate. Quick chips for HTTP / decrypted HTTPS / encrypted TLS, content types and errors.
- Detail view: request and response headers, query, cookies, raw message. The body can be shown pretty (JSON highlighting, XML, form tables), raw, as hex, or as a preview (images, media, sandboxed HTML), and downloaded.
- Copy URL / Copy as cURL / **Repeat** / **Edit & Repeat** / **Compose** new requests.
- Pause, Clear, keyboard navigation (↑/↓, j/k, Ctrl+K to filter, Esc).
- CA management: download `.pem` / `.crt`, **upload your own CA** (cert + key PEM), or regenerate one. Devices can fetch the CA from `http://<this-ip>:8080/`.
- Bypass list (globs) for apps that pin certificates; rejected handshakes are shown as errors.
- NAT-duplicate suppression. A NAT gateway sees each packet before and after translation, and only the device-side copy is kept.

### Saving sessions (**💾 Save**)

- **HAR 1.2**, for all flows or only the filtered ones. It opens in Proxyman, Charles, Chrome/Firefox DevTools, Fiddler, Insomnia, and so on. **📂 Open HAR** loads one back in.
- **PCAP** of the raw captured packets, for Wireshark or tcpdump.

Nothing persists after the process exits, so save before quitting.

## Layout

```
main.go                  flags, config file, wiring
internal/flow            in-memory store, events, HAR import/export, body decoding
internal/sniff           ssh+pcap reader, TCP reassembly, HTTP parser, TLS SNI, NAT dedup
internal/proxy           MITM proxy (CONNECT, h1/h2, WebSocket), CA + leaf certs, compose/replay
internal/tlsinfo         ClientHello/ServerHello parser
internal/server          REST + SSE API, serves embedded UI
web/                     React + Vite UI (built into web/dist, embedded via go:embed)
```

## Tests

```sh
go test ./...
# replay a real capture through the sniffer:
SNIFF_PCAP=capture.pcap go test ./internal/sniff -run PcapFile -v
```

Set `HTTPMON_DEBUG=1` to log stream parsing.
