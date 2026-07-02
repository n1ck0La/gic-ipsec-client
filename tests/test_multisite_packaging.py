from __future__ import annotations

from pathlib import Path

from gic_ipsec_client.backend.models import VpnProfile, fortigate_default_profile

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_sources_do_not_contain_site_specific_defaults() -> None:
    banned_literals = {
        "192.168.88.203",
        "see-radars.com",
        "seetech.local",
        "nextcloud.see-radars.com",
        "see-vpn.duckdns.org",
        "192.168.88.0/24",
        "ens18",
        "m.yaroshenko",
        "see-ipsec-client",
        "see-ipsec-helper",
        "see-ipsec-",
        "SEE IPsec",
        "com.see.ipsecclient",
        "seeipsec0",
    }
    scanned_roots = [
        ROOT / "src",
        ROOT / "packaging",
        ROOT / "README.md",
        ROOT / "docs",
        ROOT / "pyproject.toml",
    ]
    findings: list[str] = []

    for root in scanned_roots:
        paths = [root] if root.is_file() else [path for path in root.rglob("*") if path.is_file()]
        for path in paths:
            if path.suffix in {".pyc", ".png"}:
                continue
            text = path.read_text(encoding="utf-8")
            for literal in banned_literals:
                if literal in text:
                    findings.append(f"{path.relative_to(ROOT)} contains {literal}")

    assert findings == []


def test_profile_serialization_uses_nested_schema_without_secrets() -> None:
    profile = VpnProfile(
        id="10000000-0000-4000-8000-000000000001",
        profile_name="Acme VPN",
        gateway_fqdn_or_ip="vpn.acme.example",
        username="alice",
        eap_identity="alice@acme.example",
        psk="do-not-store-psk",
        password="do-not-store-password",
        remote_routes=["10.44.0.0/16"],
        dns_servers=["10.44.0.53"],
        dns_search_domains=["corp.acme.example"],
        dns_test_names=["portal.corp.acme.example"],
    )

    payload = profile.to_dict()

    assert set(payload) >= {"gateway", "auth", "traffic", "dns", "crypto", "platform"}
    assert payload["gateway"]["host"] == "vpn.acme.example"
    assert payload["auth"]["secret_storage"] == "keyring"
    assert payload["dns"]["test_names"] == ["portal.corp.acme.example"]
    assert "psk" not in payload["auth"]
    assert "password" not in payload["auth"]

    restored = VpnProfile.from_dict(payload)

    assert restored.gateway_fqdn_or_ip == profile.gateway_fqdn_or_ip
    assert restored.remote_routes == ["10.44.0.0/16"]
    assert restored.psk == ""
    assert restored.password == ""


def test_fortigate_preset_is_site_neutral() -> None:
    profile = fortigate_default_profile()

    assert profile.gateway_fqdn_or_ip == "vpn.example.com"
    assert profile.gateway.remote_id_mode == "any"
    assert profile.remote_routes == []
    assert profile.dns_servers == []
    assert profile.dns_search_domains == []


def test_packaging_layout_targets_requested_paths() -> None:
    nfpm = (ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8")
    deb_section = nfpm.split("  deb:", 1)[1].split("  rpm:", 1)[0]
    rpm_section = nfpm.split("  rpm:", 1)[1]
    fedora_spec = (ROOT / "packaging" / "fedora" / "gic-ipsec-client.spec").read_text(
        encoding="utf-8"
    )

    assert "name: gic-ipsec-client" in nfpm
    assert "dst: /opt/gic-ipsec-client/app" in nfpm
    assert "dst: /opt/gic-ipsec-client/venv" in nfpm
    assert "dst: /usr/bin/gic-ipsec-client" in nfpm
    assert "dst: /usr/libexec/gic-ipsec-client/gic-ipsec-helper" in nfpm
    assert "mode: 0755" in nfpm
    assert "dst: /usr/share/icons/hicolor/scalable/apps/gic-ipsec-client.svg" in nfpm
    assert "dst: /usr/share/polkit-1/actions/com.gicipsec.client.policy" in nfpm
    assert "dst: /etc/gic-ipsec-client/defaults.json" in nfpm
    assert "strongswan-swanctl" not in nfpm
    assert "/usr/sbin/swanctl" not in rpm_section
    assert "/usr/bin/swanctl" not in rpm_section
    assert "strongswan-swanctl" not in rpm_section
    assert "- swanctl" in deb_section
    assert "- strongswan" in rpm_section
    assert "Requires: strongswan" in fedora_spec
    assert "Requires: /usr/sbin/swanctl" not in fedora_spec
    assert "Requires: /usr/bin/swanctl" not in fedora_spec
    assert "- python3" in rpm_section
    assert "- polkit" in rpm_section
    assert "- NetworkManager" in rpm_section
    assert "- systemd-resolved" in rpm_section
    assert "- iproute" in rpm_section
    assert "- bind-utils" in rpm_section

    client_wrapper = ROOT / "packaging" / "bin" / "gic-ipsec-client"
    helper_wrapper = ROOT / "packaging" / "libexec" / "gic-ipsec-helper"
    policy = (ROOT / "packaging" / "polkit" / "com.gicipsec.client.policy").read_text(
        encoding="utf-8"
    )

    assert client_wrapper.exists()
    assert helper_wrapper.exists()
    assert "/opt/gic-ipsec-client/venv/bin/python -m gic_ipsec_client" in client_wrapper.read_text(
        encoding="utf-8"
    )
    assert (
        "/opt/gic-ipsec-client/venv/bin/python -m gic_ipsec_client.helper.cli"
        in helper_wrapper.read_text(encoding="utf-8")
    )
    assert "/usr/libexec/gic-ipsec-client/gic-ipsec-helper" in policy


def test_package_builder_checks_nfpm_before_creating_venv() -> None:
    script = (ROOT / "packaging" / "build-packages.sh").read_text(encoding="utf-8")

    assert script.index('command -v "$NFPM"') < script.index("python3 -m venv")
    assert "NFPM=/absolute/path/to/nfpm" in script


def test_fedora_package_smoke_workflow_installs_built_rpm() -> None:
    workflow = (ROOT / ".github" / "workflows" / "fedora-rpm-package.yml").read_text(
        encoding="utf-8"
    )
    provider_script = (
        ROOT / "packaging" / "fedora" / "validate-swanctl-provider.sh"
    ).read_text(encoding="utf-8")
    fedora_deps = (ROOT / "packaging" / "fedora" / "install-deps.sh").read_text(
        encoding="utf-8"
    )

    assert "image: fedora:latest" in workflow
    assert "build-rpm:" in workflow
    assert "install-smoke:" in workflow
    assert "needs: build-rpm" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "bash ./packaging/build-packages.sh" in workflow
    assert "dnf -y install strongswan polkit libsecret" in workflow
    assert "dnf -y install ./dist/gic-ipsec-client-*-1.x86_64.rpm" in workflow
    assert "rpm -qpR dist/gic-ipsec-client-*.rpm" in workflow
    assert "grep -F 'strongswan' rpm-requires.txt" in workflow
    assert "! grep -F '/usr/sbin/swanctl' rpm-requires.txt" in workflow
    assert "! grep -F '/usr/bin/swanctl' rpm-requires.txt" in workflow
    assert "! grep -F 'strongswan-swanctl' rpm-requires.txt" in workflow
    assert "command -v swanctl" in workflow
    assert "swanctl --version" in workflow
    assert "gic-ipsec-client --version" in workflow
    assert "dnf repoquery --whatprovides '*/swanctl'" in workflow
    assert "dnf repoquery --whatprovides '*/swanctl'" in provider_script
    assert "strongswan-swanctl" not in fedora_deps
