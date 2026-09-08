import ipaddress
import logging
import os
import subprocess
import sys
from typing import List, Optional, Tuple, Union
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

RULE_PREFIX = "CyberAttackDetectionDefense-Block-"


class BlockResult(BaseModel):
    success: bool
    status: str
    reason: str
    rule_name: str
    error: Optional[str] = None


def get_rule_name_for_ip(ip_str: str) -> str:
    """Generate deterministic application-owned firewall rule name for a normalized IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return f"{RULE_PREFIX}{ip_obj}"
    except Exception:
        return f"{RULE_PREFIX}{ip_str.strip()}"


def validate_ip_format(
    ip_str: str,
) -> Tuple[
    bool,
    str,
    Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
]:
    """
    Validates IP string format using python's ipaddress module.
    Rejects invalid formats, hostnames, command strings, CIDRs, and special-purpose addresses.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP address must be a non-empty string.", None

    ip_clean = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'", None

    if (
        ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_link_local
        or str(ip_obj) in ("0.0.0.0", "255.255.255.255")
    ):
        return False, f"Special-purpose IP address '{ip_str}' cannot be blocked.", None

    return True, "", ip_obj


class IPBlocker:
    """
    Controlled firewall adapter for IP blocking and unblocking operations.
    Executes subprocess commands without shell=True on Windows Defender Firewall.
    """

    def __init__(self, allowed_networks: Optional[List[str]] = None):
        if allowed_networks is None:
            raw_env = os.getenv("LAB_ALLOWED_NETWORKS", "")
            if raw_env:
                self.allowed_networks_raw = [
                    net.strip() for net in raw_env.split(",") if net.strip()
                ]
            else:
                self.allowed_networks_raw = []
        else:
            self.allowed_networks_raw = allowed_networks

        self._parsed_networks: List[
            Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
        ] = []
        for net_str in self.allowed_networks_raw:
            try:
                self._parsed_networks.append(
                    ipaddress.ip_network(net_str, strict=False)
                )
            except ValueError as e:
                logger.warning(
                    f"Invalid lab network format in allowlist '{net_str}': {e}"
                )

    def validate_lab_allowlist(
        self, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ) -> Tuple[bool, str]:
        """
        Validates if an IP belongs to one of the explicitly allowed lab networks.
        """
        if not self._parsed_networks:
            return False, "No allowed lab networks configured for REAL firewall mode."

        for net in self._parsed_networks:
            if ip_obj in net:
                return True, f"IP {ip_obj} is within allowed lab network {net}."

        return (
            False,
            f"IP {ip_obj} is not within any allowed lab network ({self.allowed_networks_raw}).",
        )

    def block_ip(self, ip_str: str, is_simulation: bool = False) -> BlockResult:
        """
        Blocks an IP address using Windows Defender Firewall.
        If is_simulation=True, returns SIMULATED status without running subprocess.
        """
        is_valid, err_msg, ip_obj = validate_ip_format(ip_str)
        if not is_valid:
            logger.warning(f"IP block rejected: {err_msg}")
            return BlockResult(
                success=False,
                status="REJECTED",
                reason=err_msg,
                rule_name=get_rule_name_for_ip(ip_str),
                error=err_msg,
            )

        rule_name = get_rule_name_for_ip(str(ip_obj))

        if is_simulation:
            msg = f"Simulated firewall rule '{rule_name}' created for IP {ip_obj}."
            logger.info(msg)
            return BlockResult(
                success=True,
                status="SIMULATED",
                reason=msg,
                rule_name=rule_name,
            )

        is_allowed, allow_msg = self.validate_lab_allowlist(ip_obj)
        if not is_allowed:
            logger.warning(f"Real IP block rejected: {allow_msg}")
            return BlockResult(
                success=False,
                status="REJECTED",
                reason=allow_msg,
                rule_name=rule_name,
                error=allow_msg,
            )

        if not sys.platform.startswith("win32"):
            err = f"Unsupported platform '{sys.platform}': Windows Defender Firewall is required for REAL blocking."
            logger.error(err)
            return BlockResult(
                success=False,
                status="FAILED",
                reason=err,
                rule_name=rule_name,
                error=err,
            )

        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_obj}",
        ]

        logger.info(f"Executing real firewall command: {cmd}")
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, shell=False
            )
            if res.returncode == 0:
                msg = (
                    f"Firewall rule '{rule_name}' successfully added for IP {ip_obj}."
                )
                logger.info(msg)
                return BlockResult(
                    success=True,
                    status="SUCCESS",
                    reason=msg,
                    rule_name=rule_name,
                )
            else:
                stderr = res.stderr.strip() or res.stdout.strip()
                err = f"Firewall command failed (exit code {res.returncode}): {stderr}"
                logger.error(err)
                return BlockResult(
                    success=False,
                    status="FAILED",
                    reason=err,
                    rule_name=rule_name,
                    error=err,
                )
        except Exception as ex:
            err = f"Subprocess execution error: {ex}"
            logger.error(err, exc_info=True)
            return BlockResult(
                success=False,
                status="FAILED",
                reason=err,
                rule_name=rule_name,
                error=err,
            )

    def unblock_ip(self, ip_str: str, is_simulation: bool = False) -> BlockResult:
        """
        Removes application-owned firewall rule for an IP address.
        """
        is_valid, err_msg, ip_obj = validate_ip_format(ip_str)
        if not is_valid:
            return BlockResult(
                success=False,
                status="REJECTED",
                reason=err_msg,
                rule_name=get_rule_name_for_ip(ip_str),
                error=err_msg,
            )

        rule_name = get_rule_name_for_ip(str(ip_obj))

        if is_simulation:
            msg = f"Simulated unblock of rule '{rule_name}' for IP {ip_obj}."
            logger.info(msg)
            return BlockResult(
                success=True,
                status="SIMULATED",
                reason=msg,
                rule_name=rule_name,
            )

        if not sys.platform.startswith("win32"):
            err = f"Unsupported platform '{sys.platform}'."
            return BlockResult(
                success=False,
                status="FAILED",
                reason=err,
                rule_name=rule_name,
                error=err,
            )

        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

        logger.info(f"Executing firewall unblock: {cmd}")
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, shell=False
            )
            if res.returncode == 0:
                msg = f"Firewall rule '{rule_name}' successfully removed."
                logger.info(msg)
                return BlockResult(
                    success=True, status="SUCCESS", reason=msg, rule_name=rule_name
                )
            else:
                err = f"Unblock command failed: {res.stderr.strip() or res.stdout.strip()}"
                logger.error(err)
                return BlockResult(
                    success=False,
                    status="FAILED",
                    reason=err,
                    rule_name=rule_name,
                    error=err,
                )
        except Exception as ex:
            err = f"Subprocess unblock error: {ex}"
            logger.error(err, exc_info=True)
            return BlockResult(
                success=False,
                status="FAILED",
                reason=err,
                rule_name=rule_name,
                error=err,
            )

