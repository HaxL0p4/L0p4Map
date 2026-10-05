"""Nmap scan presets and validation shared by the command preview and runner."""

import re
import shlex

TCP_FLAGS = ("-sS", "-sT", "-sN", "-sX")
PORT_FLAGS = ("", "-F", "-p-")
TIMING_FLAGS = ("-T1", "-T2", "-T3", "-T4", "-T5")
SCAN_PRESETS = {
    "basic": ("-sT", "-F", "--open", "-T3"),
    "complete": ("-sS", "-sU", "-p-", "-sV", "-O", "-sC", "--reason", "-T3"),
}
# Values of these options may look like scan flags; do not interpret them as options.
VALUE_OPTIONS = {
    "--script-args", "--script-args-file", "--exclude", "--excludefile", "-iL",
    "-oN", "-oX", "-oG", "-oA", "-oS", "--datadir", "--servicedb", "--versiondb",
    "--dns-servers", "-e", "-S", "--source-port", "-g", "--proxies",
    "--host-timeout", "--max-retries", "--min-rate", "--max-rate", "--data-string",
}


def build_scan_command(selected, custom, target):
    target = target.strip()
    if not target or target.startswith("-"):
        raise ValueError("Enter a valid target before running.")
    args = []
    for flag in selected:
        args.extend(shlex.split(flag))
    try:
        args.extend(shlex.split(custom))
    except ValueError as exc:
        raise ValueError("Check the quoting in custom flags.") from exc

    tcp = set()
    sctp = set()
    udp = False
    os_detection = False
    os_guess = False
    non_port_scan = False
    ports = []
    timings = set()
    scripts = []
    cleaned = []
    default_script_indices = set()
    default_scripts = False
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        if token == "--script" or token.startswith("--script="):
            if token == "--script":
                if index >= len(args) or args[index].startswith("-"):
                    raise ValueError("Enter a script name or category after --script.")
                value = args[index]
                index += 1
            else:
                value = token.partition("=")[2]
            if not value:
                raise ValueError("Enter a valid script selection.")
            if value not in scripts:
                scripts.append(value)
            continue
        cleaned.append(token)
        if token == "-sC":
            default_script_indices.add(len(cleaned) - 1)
        if token in VALUE_OPTIONS:
            if index >= len(args):
                raise ValueError(f"Enter a value after {token}.")
            cleaned.append(args[index])
            index += 1
            continue
        os_detection |= token in ("-O", "-A")
        os_guess |= token == "--osscan-guess"
        default_scripts |= token == "-A"
        if token == "-s":
            if index >= len(args):
                raise ValueError("Enter the scan method after -s.")
            modes = args[index]
            cleaned.append(modes)
            index += 1
        elif token.startswith("-sI"):
            modes = "I"
            if token == "-sI":
                if index >= len(args):
                    raise ValueError("Enter the idle scan host after -sI.")
                cleaned.append(args[index])
                index += 1
        else:
            match = re.fullmatch(r"-s([A-Za-z]+)", token)
            modes = match.group(1) if match else ""
        tcp.update(set(modes) & set("STNAWFMXI"))
        sctp.update(set(modes) & set("YZ"))
        udp |= "U" in modes
        non_port_scan |= bool(set(modes) & set("nLPO"))
        default_scripts |= "C" in modes
        if token.startswith("-b"):
            tcp.add("b")
            if token == "-b":
                if index >= len(args):
                    raise ValueError("Enter the FTP server after -b.")
                cleaned.append(args[index])
                index += 1
        if token == "-F" or token.startswith("-p") or token.split("=")[0] in ("--top-ports", "--port-ratio"):
            ports.append(token)
            if token in ("-p", "--top-ports", "--port-ratio"):
                if index >= len(args) or args[index].startswith("-"):
                    raise ValueError(f"Enter the port range after {token}.")
                cleaned.append(args[index])
                index += 1
        if token.startswith("-T"):
            timing = token[2:]
            if not timing:
                if index >= len(args):
                    raise ValueError("Enter the timing level after -T.")
                timing = args[index]
                cleaned.append(timing)
                index += 1
            timing = {"paranoid": "0", "sneaky": "1", "polite": "2", "normal": "3",
                      "aggressive": "4", "insane": "5"}.get(timing.lower(), timing)
            timings.add(timing)

    if len(tcp) > 1:
        raise ValueError("Choose only one TCP method. UDP can be combined with it.")
    if len(sctp) > 1:
        raise ValueError("Choose only one SCTP method.")
    if non_port_scan and (tcp or sctp or ports or udp):
        raise ValueError("Discovery, list, or IP protocol scanning cannot be combined with port scanning.")
    if len(ports) > 1:
        raise ValueError("Choose only one port range: fast, all, or custom flags.")
    if len(timings) > 1:
        raise ValueError("Choose only one timing level.")
    if os_guess and not os_detection:
        raise ValueError("OS guess requires OS detection (-O or -A).")
    if scripts:
        if default_scripts and "default" not in scripts:
            scripts.insert(0, "default")
        cleaned = [flag for index, flag in enumerate(cleaned) if index not in default_script_indices]
        cleaned.extend(("--script", ",".join(scripts)))
    return ["nmap", *cleaned, target]
