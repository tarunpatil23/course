from __future__ import annotations

from pathlib import Path
from typing import Iterable

from defusedxml import ElementTree as DefusedET

from .models import CatalogMetadata, CWEEntry

MAX_XML_BYTES = 70 * 1024 * 1024
SECURITY_SCOPES = {
    "confidentiality",
    "integrity",
    "availability",
    "access control",
    "authentication",
    "authorization",
    "accountability",
    "non-repudiation",
    "other",
}
SECURITY_IMPACTS = {
    "read application data",
    "modify application data",
    "gain privileges or assume identity",
    "bypass protection mechanism",
    "do\u0053: resource consumption (cpu)",
    "do\u0053: resource consumption (memory)",
    "do\u0053: resource consumption (other)",
    "execute unauthorized code or commands",
    "hide activities",
}
QUALITY_ONLY_IMPACTS = {
    "reduce maintainability",
    "increase analytical complexity",
    "reduce performance",
    "reduce reliability",
}


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def first_child(element, name: str):
    for child in list(element):
        if local_name(child.tag) == name:
            return child
    return None


def children_named(element, name: str) -> list:
    return [child for child in list(element) if local_name(child.tag) == name]


def text_content(element) -> str:
    if element is None:
        return ""
    return " ".join(part.strip() for part in element.itertext() if part and part.strip())


def _clean_text_list(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for value in values:
        item = " ".join(value.split())
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned


def _text_list(elements: Iterable) -> list[str]:
    return _clean_text_list(text_content(element) for element in elements)


def safe_read_xml_bytes(path: Path) -> bytes:
    payload = path.read_bytes()
    if len(payload) > MAX_XML_BYTES:
        raise ValueError(f"Refusing to read oversized XML file: {path}")
    return payload


def parse_catalog(path: Path) -> tuple[CatalogMetadata, list[CWEEntry]]:
    xml_bytes = safe_read_xml_bytes(path)
    root = DefusedET.fromstring(xml_bytes)
    metadata = CatalogMetadata(
        name=root.attrib.get("Name", "CWE Catalog"),
        version=root.attrib.get("Version", "unknown"),
        date=root.attrib.get("Date", "unknown"),
    )
    weaknesses_parent = first_child(root, "Weaknesses")
    if weaknesses_parent is None:
        return metadata, []
    entries: list[CWEEntry] = []
    for weakness in children_named(weaknesses_parent, "Weakness"):
        entries.append(_parse_weakness(weakness))
    return metadata, entries


def parse_top25_members(path: Path) -> set[int]:
    root = DefusedET.fromstring(safe_read_xml_bytes(path))
    members: set[int] = set()
    weaknesses_parent = first_child(root, "Weaknesses")
    if weaknesses_parent is not None:
        for weakness in children_named(weaknesses_parent, "Weakness"):
            member_id = weakness.attrib.get("ID")
            if member_id and member_id.isdigit():
                members.add(int(member_id))
    return members


def _parse_weakness(weakness) -> CWEEntry:
    cwe_id = int(weakness.attrib["ID"])
    name = weakness.attrib.get("Name", f"CWE-{cwe_id}")
    abstraction = weakness.attrib.get("Abstraction", "Unknown")
    status = weakness.attrib.get("Status", "Unknown")
    description = text_content(first_child(weakness, "Description"))
    extended_description = text_content(first_child(weakness, "Extended_Description"))
    likelihood_of_exploit = text_content(first_child(weakness, "Likelihood_Of_Exploit")) or "Unknown"

    scopes: list[str] = []
    impacts: list[str] = []
    consequence_likelihoods: list[str] = []
    consequences_parent = first_child(weakness, "Common_Consequences")
    if consequences_parent is not None:
        for consequence in children_named(consequences_parent, "Consequence"):
            scopes.extend(_text_list(children_named(consequence, "Scope")))
            impacts.extend(_text_list(children_named(consequence, "Impact")))
            consequence_likelihoods.extend(_text_list(children_named(consequence, "Likelihood")))

    detection_effectiveness: list[str] = []
    detection_parent = first_child(weakness, "Detection_Methods")
    if detection_parent is not None:
        for method in children_named(detection_parent, "Detection_Method"):
            detection_effectiveness.extend(_text_list(children_named(method, "Effectiveness")))

    mitigation_effectiveness: list[str] = []
    mitigation_parent = first_child(weakness, "Potential_Mitigations")
    if mitigation_parent is not None:
        for mitigation in children_named(mitigation_parent, "Mitigation"):
            mitigation_effectiveness.extend(_text_list(children_named(mitigation, "Effectiveness")))

    platform_prevalence: list[str] = []
    applicable_platforms = first_child(weakness, "Applicable_Platforms")
    if applicable_platforms is not None:
        for item in applicable_platforms.iter():
            prevalence = item.attrib.get("Prevalence")
            if prevalence:
                platform_prevalence.append(prevalence)

    related_weakness_count = 0
    related_attack_pattern_count = 0
    observed_example_count = 0

    related_parent = first_child(weakness, "Related_Weaknesses")
    if related_parent is not None:
        related_weakness_count = len(children_named(related_parent, "Related_Weakness"))

    capec_parent = first_child(weakness, "Related_Attack_Patterns")
    if capec_parent is not None:
        related_attack_pattern_count = len(children_named(capec_parent, "Related_Attack_Pattern"))

    observed_parent = first_child(weakness, "Observed_Examples")
    if observed_parent is not None:
        observed_example_count = len(children_named(observed_parent, "Observed_Example"))

    modes_of_introduction: list[str] = []
    modes_parent = first_child(weakness, "Modes_Of_Introduction")
    if modes_parent is not None:
        for introduction in children_named(modes_parent, "Introduction"):
            modes_of_introduction.extend(_text_list(children_named(introduction, "Phase")))

    mapping_usage = "Unknown"
    mapping_notes = first_child(weakness, "Mapping_Notes")
    if mapping_notes is not None:
        mapping_usage = text_content(first_child(mapping_notes, "Usage")) or "Unknown"

    entry = CWEEntry(
        cwe_id=cwe_id,
        name=name,
        abstraction=abstraction,
        status=status,
        description=description,
        extended_description=extended_description,
        likelihood_of_exploit=likelihood_of_exploit,
        scopes=_clean_text_list(scopes),
        impacts=_clean_text_list(impacts),
        consequence_likelihoods=_clean_text_list(consequence_likelihoods),
        detection_effectiveness=_clean_text_list(detection_effectiveness),
        mitigation_effectiveness=_clean_text_list(mitigation_effectiveness),
        platform_prevalence=_clean_text_list(platform_prevalence),
        related_weakness_count=related_weakness_count,
        related_attack_pattern_count=related_attack_pattern_count,
        observed_example_count=observed_example_count,
        modes_of_introduction=_clean_text_list(modes_of_introduction),
        mapping_usage=mapping_usage,
    )
    entry.security_relevant, entry.exclusions = evaluate_security_relevance(entry)
    return entry


def evaluate_security_relevance(entry: CWEEntry) -> tuple[bool, list[str]]:
    exclusions: list[str] = []
    if entry.mapping_usage.strip().lower() == "prohibited":
        exclusions.append("MITRE mapping notes mark this entry as prohibited for vulnerability mapping.")

    normalized_scopes = {value.strip().lower() for value in entry.scopes}
    normalized_impacts = {value.strip().lower() for value in entry.impacts}

    has_security_scope = bool(normalized_scopes & SECURITY_SCOPES)
    has_security_impact = bool(normalized_impacts & SECURITY_IMPACTS)
    quality_only = bool(normalized_impacts) and normalized_impacts.issubset(QUALITY_ONLY_IMPACTS)

    if quality_only and not has_security_scope:
        exclusions.append("Entry only exposes quality-oriented impacts such as maintainability or performance.")

    if not has_security_scope and not has_security_impact and not entry.observed_example_count and not entry.related_attack_pattern_count:
        exclusions.append("Entry lacks strong direct security signals in scopes, impacts, observed CVEs, or CAPEC relationships.")

    return len(exclusions) == 0, exclusions
