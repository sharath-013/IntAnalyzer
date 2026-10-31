"""Deterministic rules. These, not the LLM, decide every verdict and severity."""

RULES: dict[str, str] = {
    "IA-INTEGRITY-001": "Tarball hash does not match the registry's dist.integrity / dist.shasum.",
    "IA-MANIFEST-001": "Install-time lifecycle script (preinstall/install/postinstall, or a "
    "package-only prepare) added or changed versus the source package.json.",
    "IA-MANIFEST-002": "Dependency or optionalDependency in the package that the source "
    "package.json does not declare.",
    "IA-MANIFEST-003": "New dependency whose name is 1-2 edits away from a well-known package "
    "or an existing dependency (possible typosquat).",
    "IA-MANIFEST-004": "main / bin / exports points at a file that exists only in the package "
    "and is not build output of any source file.",
    "IA-MANIFEST-005": "Other package.json field differs from the source (version, gitHead and "
    "_-prefixed fields are ignored).",
    "IA-MANIFEST-006": "Registry metadata disagrees with the tarball's package.json on scripts "
    "or dependencies (manifest confusion).",
    "IA-CODE-001": "File without a source counterpart (or build output) contains obfuscation "
    "or dangerous APIs that its source does not.",
    "IA-CODE-002": "File present in both trees, where the package version adds dangerous APIs "
    "absent from the source version.",
    "IA-FILE-001": "File found nowhere in the repository and not explained as build output.",
    "IA-FILE-002": "File present in both trees with different content.",
}
