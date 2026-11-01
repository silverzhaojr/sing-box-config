#!/opt/homebrew/bin/python3.14

"""Convert proxy subscriptions into sing-box outbounds with per-country and predefined groups."""

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

DEFAULT_USER_AGENT = "sing-box 1.14.4"
GROUP_FILTER_KEYS = ("filter", "exclude", "subscription")
NON_PROXY_TYPES = {"direct", "block", "dns", "selector", "urltest"}
DROPPED_NODE_KEYS = ("domain_resolver", "detour")
FETCH_ATTEMPTS = 4


@dataclass
class Subscription:
    name: str
    url: str
    exclude: str = ""
    group: str = ""
    udp: bool = True
    skip_cert_verify: bool = False
    user_agent: str = DEFAULT_USER_AGENT


@dataclass
class Node:
    subscription: str
    outbound: dict

    @property
    def tag(self):
        return self.outbound["tag"]


def warn(message):
    print(f"warning: {message}", file=sys.stderr)


def info(message):
    print(message, file=sys.stderr)


def truthy(value):
    return value is not None and value.lower() in ("1", "true", "yes")


def b64decode(text):
    text = "".join(text.split())
    text += "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(
            text.replace("+", "-").replace("/", "_")
        ).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def split_link(link):
    url = urllib.parse.urlsplit(link)
    query = {
        key: values[-1]
        for key, values in urllib.parse.parse_qs(
            url.query, keep_blank_values=True
        ).items()
    }
    if not url.hostname or url.port is None:
        raise ValueError("missing server address or port")
    tag = urllib.parse.unquote(url.fragment).strip() or f"{url.hostname}:{url.port}"
    return url, query, tag


def build_tls(query, subscription, security):
    if security not in ("tls", "reality", "xtls"):
        return None
    tls = {"enabled": True}
    server_name = query.get("sni") or query.get("peer") or query.get("host")
    if server_name:
        tls["server_name"] = server_name
    if (
        subscription.skip_cert_verify
        or truthy(query.get("allowInsecure"))
        or truthy(query.get("insecure"))
    ):
        tls["insecure"] = True
    if query.get("alpn"):
        tls["alpn"] = query["alpn"].split(",")
    fingerprint = query.get("fp")
    if security == "reality" and not fingerprint:
        fingerprint = "chrome"
    if fingerprint and fingerprint != "none":
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": query.get("pbk", ""),
            "short_id": query.get("sid", ""),
        }
    return tls


def build_transport(query):
    transport_type = query.get("type", "tcp")
    if transport_type in ("", "tcp", "raw"):
        if query.get("headerType", "none") != "none":
            raise ValueError(f"unsupported tcp header type: {query['headerType']}")
        return None
    host = query.get("host")
    path = query.get("path") or "/"
    if transport_type == "ws":
        transport = {"type": "ws", "path": path}
        early_data = re.search(r"[?&]ed=(\d+)", path)
        if early_data:
            transport["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            transport["max_early_data"] = int(early_data[1])
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if transport_type == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host:
            transport["host"] = host
        return transport
    if transport_type == "grpc":
        return {"type": "grpc", "service_name": query.get("serviceName", "")}
    if transport_type in ("http", "h2"):
        transport = {"type": "http", "path": path}
        if host:
            transport["host"] = host.split(",")
        return transport
    raise ValueError(f"unsupported transport: {transport_type}")


def finish(outbound, subscription, tls=None, transport=None):
    if not subscription.udp:
        outbound["network"] = "tcp"
    if tls:
        outbound["tls"] = tls
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vless(link, subscription):
    url, query, tag = split_link(link)
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": url.hostname,
        "server_port": url.port,
        "uuid": urllib.parse.unquote(url.username or ""),
    }
    if query.get("flow"):
        outbound["flow"] = query["flow"]
    if query.get("packetEncoding"):
        outbound["packet_encoding"] = query["packetEncoding"]
    tls = build_tls(query, subscription, query.get("security", "none"))
    return finish(outbound, subscription, tls, build_transport(query))


def parse_trojan(link, subscription):
    url, query, tag = split_link(link)
    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": url.hostname,
        "server_port": url.port,
        "password": urllib.parse.unquote(url.username or ""),
    }
    tls = build_tls(query, subscription, query.get("security", "tls"))
    return finish(outbound, subscription, tls, build_transport(query))


def parse_hysteria2(link, subscription):
    url, query, tag = split_link(link)
    auth = url.netloc.rsplit("@", 1)[0] if "@" in url.netloc else ""
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": url.hostname,
        "server_port": url.port,
        "password": urllib.parse.unquote(auth),
    }
    ports = query.get("mport") or query.get("ports")
    if ports:
        outbound["server_ports"] = [
            p.replace("-", ":") if "-" in p else f"{p}:{p}" for p in ports.split(",")
        ]
    if query.get("obfs") == "salamander":
        outbound["obfs"] = {
            "type": "salamander",
            "password": query.get("obfs-password", ""),
        }
    tls = build_tls(query, subscription, "tls")
    tls.pop("utls", None)
    return finish(outbound, subscription, tls)


def parse_shadowsocks(link, subscription):
    body, _, fragment = link[len("ss://") :].partition("#")
    body, _, query = body.partition("?")
    body = body.rstrip("/")
    if "@" in body:
        user_info, _, host_port = body.rpartition("@")
        user_info = urllib.parse.unquote(user_info)
        if ":" not in user_info:
            user_info = b64decode(user_info) or ""
    else:
        decoded = b64decode(body)
        if not decoded or "@" not in decoded:
            raise ValueError("invalid shadowsocks link")
        user_info, _, host_port = decoded.rpartition("@")
    method, _, password = user_info.partition(":")
    host, _, port = host_port.rpartition(":")
    if not method or not host or not port.isdigit():
        raise ValueError("invalid shadowsocks link")
    outbound = {
        "type": "shadowsocks",
        "tag": urllib.parse.unquote(fragment).strip() or host_port,
        "server": host.strip("[]"),
        "server_port": int(port),
        "method": method,
        "password": password,
    }
    plugin = urllib.parse.parse_qs(query).get("plugin")
    if plugin:
        name, _, options = plugin[0].partition(";")
        outbound["plugin"] = "obfs-local" if name == "simple-obfs" else name
        outbound["plugin_opts"] = options
    return finish(outbound, subscription)


PARSERS = {
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "ss": parse_shadowsocks,
}


def resolve_url(subscription):
    if not subscription.url.startswith("env:"):
        return subscription.url
    variable = subscription.url[len("env:") :]
    url = os.environ.get(variable, "")
    if not url:
        raise ValueError(f"environment variable {variable} is not set")
    return url


def proxy_handler():
    proxies = urllib.request.getproxies()
    fallback = proxies.pop("all", None)
    proxies.pop("no", None)
    for scheme in ("http", "https"):
        if fallback:
            proxies.setdefault(scheme, fallback)
        if proxies.get(scheme, "").startswith("socks"):
            raise ValueError(
                f"SOCKS proxy {proxies[scheme]} is not supported, use an HTTP proxy"
            )
    return urllib.request.ProxyHandler(proxies)


def fetch(subscription, timeout):
    opener = urllib.request.build_opener(proxy_handler())
    request = urllib.request.Request(
        resolve_url(subscription), headers={"User-Agent": subscription.user_agent}
    )
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace"), response.headers
        except (urllib.error.URLError, TimeoutError) as error:
            retryable = (
                not isinstance(error, urllib.error.HTTPError)
                or error.code in (403, 429)
                or error.code >= 500
            )
            if not retryable or attempt == FETCH_ATTEMPTS:
                raise
            warn(f"[{subscription.name}] download failed ({error}), retrying")
            time.sleep(3 * attempt)


def report_usage(subscription, headers):
    fields = dict(
        item.strip().split("=", 1)
        for item in (headers.get("subscription-userinfo") or "").split(";")
        if "=" in item
    )
    try:
        used = int(fields.get("upload") or 0) + int(fields.get("download") or 0)
        total = int(fields.get("total") or 0)
    except ValueError:
        return
    if not total:
        return
    expire = fields.get("expire", "")
    expire_text = (
        datetime.fromtimestamp(int(expire)).strftime("%Y-%m-%d")
        if expire.isdigit() and int(expire)
        else "never"
    )
    info(
        f"[{subscription.name}] used {used / 2**30:.1f} GiB of {total / 2**30:.1f} GiB, expires {expire_text}"
    )


def parse_singbox_json(content, subscription):
    outbounds = []
    for outbound in json.loads(content).get("outbounds", []):
        if outbound.get("type") in NON_PROXY_TYPES or "server" not in outbound:
            continue
        for key in DROPPED_NODE_KEYS:
            outbound.pop(key, None)
        if not subscription.udp:
            outbound["network"] = "tcp"
        if subscription.skip_cert_verify and "tls" in outbound:
            outbound["tls"]["insecure"] = True
        outbounds.append(outbound)
    return outbounds


def parse_links(content, subscription):
    decoded = b64decode(content.strip())
    text = decoded if decoded and "://" in decoded else content
    outbounds = []
    for line in filter(None, (line.strip() for line in text.splitlines())):
        scheme = line.split("://", 1)[0].lower()
        parser = PARSERS.get(scheme)
        if parser is None:
            warn(f"[{subscription.name}] skipped unsupported link type: {scheme}://")
            continue
        try:
            outbounds.append(parser(line, subscription))
        except (ValueError, KeyError) as error:
            warn(f"[{subscription.name}] skipped invalid {scheme}:// link: {error}")
    return outbounds


def parse_subscription(content, subscription):
    if content.lstrip().startswith("{"):
        outbounds = parse_singbox_json(content, subscription)
    else:
        outbounds = parse_links(content, subscription)
    return [
        Node(subscription.name, outbound)
        for outbound in outbounds
        if not (
            subscription.exclude and re.search(subscription.exclude, outbound["tag"])
        )
    ]


def build_country_groups(specs, nodes, urltest_defaults):
    groups = []
    for spec in specs:
        spec = {"type": "urltest", **spec}
        if "filter" not in spec:
            raise ValueError(f"country {spec['tag']} needs a filter")
        if not any(re.search(spec["filter"], node.tag) for node in nodes):
            info(f"country {spec['tag']} matched no nodes, skipped")
            continue
        groups.append(build_group(spec, nodes, {}, urltest_defaults))
    return groups


def build_subscription_groups(subscriptions, nodes, urltest_defaults):
    return [
        build_group(
            {
                "type": "urltest",
                "tag": subscription.group,
                "subscription": subscription.name,
            },
            nodes,
            {},
            urltest_defaults,
        )
        for subscription in subscriptions
        if subscription.group
    ]


def dedupe_tags(nodes, reserved):
    seen = set(reserved)
    for node in nodes:
        tag, index = node.tag, 2
        while node.outbound["tag"] in seen:
            node.outbound["tag"] = f"{tag} {index}"
            index += 1
        seen.add(node.outbound["tag"])


def assemble_groups(group_specs, generated, nodes, urltest_defaults):
    # generated maps a placeholder ("{countries}") to its list of generated groups.
    # A [[groups]] entry of only {expand = "{countries}"} splices those groups in at that
    # position; anything referenced in members is expanded via placeholders; whatever is not
    # placed by a marker is appended at the end, so the output stays complete.
    placeholders = {name: [g["tag"] for g in groups] for name, groups in generated.items()}
    groups = []
    placed = set()
    for spec in group_specs:
        name = spec.get("expand")
        if name is None:
            groups.append(build_group(spec, nodes, placeholders, urltest_defaults))
        elif name in generated:
            groups += generated[name]
            placed.add(name)
        else:
            raise ValueError(f"unknown expand placeholder: {name}")
    for name, generated_groups in generated.items():
        if name not in placed:
            groups += generated_groups
    return groups


def build_group(spec, nodes, placeholders, urltest_defaults):
    members = []
    for tag in spec.get("outbounds", []):
        members += placeholders.get(tag, [tag])
    if any(key in spec for key in ("filter", "subscription")):
        pool = nodes
        if "subscription" in spec:
            names = spec["subscription"]
            names = [names] if isinstance(names, str) else names
            pool = [node for node in pool if node.subscription in names]
        if "filter" in spec:
            pool = [node for node in pool if re.search(spec["filter"], node.tag)]
        if "exclude" in spec:
            pool = [node for node in pool if not re.search(spec["exclude"], node.tag)]
        members += [node.tag for node in pool if node.tag not in members]
    if not members:
        warn(f"group {spec['tag']} matched no nodes, using DIRECT")
        members = ["DIRECT"]
    group = {"type": spec["type"], "tag": spec["tag"], "outbounds": members}
    if spec["type"] == "urltest":
        group.update(urltest_defaults)
    group.update(
        {
            key: value
            for key, value in spec.items()
            if key not in ("type", "tag", "outbounds", *GROUP_FILTER_KEYS)
        }
    )
    return group


def generate(config, timeout):
    subscriptions = [Subscription(**item) for item in config.get("subscriptions", [])]
    if not subscriptions:
        raise ValueError("no [[subscriptions]] configured")
    nodes = []
    for subscription in subscriptions:
        content, headers = fetch(subscription, timeout)
        parsed = parse_subscription(content, subscription)
        if not parsed:
            raise ValueError(
                f"subscription {subscription.name} returned no usable nodes"
            )
        info(f"[{subscription.name}] {len(parsed)} nodes")
        report_usage(subscription, headers)
        nodes += parsed

    urltest_defaults = config.get("urltest", {})
    extra_outbounds = config.get("outbounds", [])
    group_specs = config.get("groups", [])
    country_specs = config.get("countries", [])
    real_specs = [s for s in group_specs if "expand" not in s]
    reserved = [o["tag"] for o in extra_outbounds] + [
        g["tag"] for g in real_specs + country_specs
    ]
    dedupe_tags(nodes, reserved + [s.group for s in subscriptions if s.group])
    subscription_groups = build_subscription_groups(
        subscriptions, nodes, urltest_defaults
    )
    country_groups = build_country_groups(country_specs, nodes, urltest_defaults)
    if country_groups:
        info(
            "country groups: "
            + ", ".join(
                f"{group['tag']} ({len(group['outbounds'])})"
                for group in country_groups
            )
        )
    generated = {
        "{subscriptions}": subscription_groups,
        "{countries}": country_groups,
    }
    groups = assemble_groups(group_specs, generated, nodes, urltest_defaults)

    known = (
        {o["tag"] for o in extra_outbounds}
        | {n.tag for n in nodes}
        | {g["tag"] for g in groups}
    )
    for group in groups:
        missing = [tag for tag in group["outbounds"] if tag not in known]
        if missing:
            raise ValueError(
                f"group {group['tag']} references unknown outbounds: {', '.join(missing)}"
            )
    return {"outbounds": extra_outbounds + [n.outbound for n in nodes] + groups}


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Downloads honor HTTP_PROXY, HTTPS_PROXY and NO_PROXY (HTTP proxies only).",
    )
    parser.add_argument(
        "-c",
        "--config",
        default="groups.toml",
        help="group definition file (default: groups.toml)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="outbounds.json",
        help="output file (default: outbounds.json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="download timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    with open(args.config, "rb") as file:
        config = tomllib.load(file)
    try:
        result = generate(config, args.timeout)
    except (OSError, ValueError, re.error) as error:
        sys.exit(f"error: {error}")

    output = Path(args.output)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, suffix=".json", delete=False
    ) as file:
        json.dump(result, file, ensure_ascii=False, indent=2)
        file.write("\n")
    os.replace(file.name, output)
    info(f"wrote {output}")


if __name__ == "__main__":
    main()
