"""
AegisNIDS Automated STIX 2.1 Specification & Schema Conformance Suite.
Validates exported STIX 2.1 bundle (app/data/stix2_bundle_export.json) against:
- OASIS STIX 2.1 Part 1 & Part 2 Specification rules
- STIX Object and Bundle Grammar
- STIX Pattern Syntax Validator (stix2-patterns parser)
- Official python-stix2 Library Deserializer (stix2.parse)
"""
import os
import sys
import json
import re
import uuid
from datetime import datetime
import stix2
from stix2patterns.v21.pattern import Pattern

UUID4_REGEX = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$', re.IGNORECASE)

def test_stix_export():
    bundle_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app", "data", "stix2_bundle_export.json")
    print("=" * 80)
    print("  AEGIS NIDS — AUTOMATED STIX 2.1 SCHEMA & CONFORMANCE VALIDATION")
    print("=" * 80)
    print(f"[*] Checking STIX bundle at: {bundle_path}")

    # [1] File existence and JSON syntax
    assert os.path.exists(bundle_path), f"STIX export file not found: {bundle_path}"
    with open(bundle_path, 'r', encoding='utf-8') as f:
        raw_content = f.read()
        data = json.loads(raw_content)
    print("    [PASS] 1. Valid JSON syntax verified.")

    # [2] Bundle structure
    assert isinstance(data, dict), "Top-level STIX entity must be a JSON object"
    assert data.get('type') == 'bundle', f"Expected type 'bundle', got {data.get('type')}"
    assert 'id' in data, "Bundle missing 'id' property"
    bundle_id = data['id']
    assert bundle_id.startswith('bundle--'), f"Bundle ID must start with 'bundle--', got {bundle_id}"
    bundle_uuid = bundle_id.replace('bundle--', '')
    assert UUID4_REGEX.match(bundle_uuid), f"Invalid UUIDv4 in bundle id: {bundle_uuid}"
    assert 'objects' in data and isinstance(data['objects'], list), "Bundle must contain an 'objects' list"
    assert len(data['objects']) > 0, "Bundle objects list cannot be empty"
    print(f"    [PASS] 2. STIX Bundle container valid ({len(data['objects'])} objects).")

    # [3] Object checks: IDs, Timestamps, Duplicates
    seen_ids = set()
    seen_indicators = set()
    identities = []
    indicators = []

    for idx, obj in enumerate(data['objects']):
        assert isinstance(obj, dict), f"Object at index {idx} is not a dictionary"
        obj_type = obj.get('type')
        obj_id = obj.get('id')
        assert obj_type, f"Object at index {idx} missing 'type'"
        assert obj_id, f"Object at index {idx} missing 'id'"
        assert obj_id.startswith(f"{obj_type}--"), f"Object ID prefix does not match type: {obj_id}"
        
        # UUID check
        raw_uuid = obj_id.split('--', 1)[1]
        assert UUID4_REGEX.match(raw_uuid), f"Object {obj_id} has invalid UUIDv4: {raw_uuid}"
        
        # Duplicate check
        assert obj_id not in seen_ids, f"Duplicate object ID detected: {obj_id}"
        seen_ids.add(obj_id)

        # STIX 2.1 spec_version check
        assert obj.get('spec_version') == '2.1', f"Object {obj_id} spec_version != '2.1'"

        # Timestamp validation (ISO-8601 UTC)
        for ts_field in ['created', 'modified']:
            assert ts_field in obj, f"Object {obj_id} missing {ts_field}"
            ts_str = obj[ts_field]
            assert ts_str.endswith('Z'), f"{ts_field} must be UTC timestamp ending with 'Z': {ts_str}"
            try:
                # Validate parseable datetime
                datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except Exception as e:
                raise AssertionError(f"Malformed timestamp in {obj_id}.{ts_field}: {ts_str}")

        if obj_type == 'identity':
            identities.append(obj)
            assert 'name' in obj and obj['name'], "Identity missing 'name'"
            assert obj.get('identity_class') in ['individual', 'group', 'system', 'organization', 'class', 'unknown'], (
                f"Invalid identity_class: {obj.get('identity_class')}"
            )
        elif obj_type == 'indicator':
            indicators.append(obj)
            # Pattern validation
            assert 'pattern' in obj, f"Indicator {obj_id} missing 'pattern'"
            assert obj.get('pattern_type') == 'stix', f"Indicator {obj_id} pattern_type != 'stix'"
            assert obj.get('pattern_version') == '2.1', f"Indicator {obj_id} pattern_version != '2.1'"
            
            pattern_str = obj['pattern']
            # Syntactic validation with official stix2patterns parser
            try:
                parsed_pat = Pattern(pattern_str)
                assert parsed_pat is not None
            except Exception as e:
                raise AssertionError(f"Invalid STIX 2.1 pattern '{pattern_str}' in {obj_id}: {e}")

            # Confidence check
            conf = obj.get('confidence')
            assert conf is not None, f"Indicator {obj_id} missing 'confidence'"
            assert isinstance(conf, int) and 0 <= conf <= 100, f"Confidence must be int 0-100, got {conf}"

            # Indicator types check
            ind_types = obj.get('indicator_types')
            assert isinstance(ind_types, list) and len(ind_types) > 0, f"Indicator {obj_id} invalid indicator_types"

            # Check MITRE external references
            if 'external_references' in obj:
                for ref in obj['external_references']:
                    assert 'source_name' in ref, f"External reference in {obj_id} missing 'source_name'"
                    assert 'external_id' in ref, f"External reference in {obj_id} missing 'external_id'"

            # Prevent duplicate indicator patterns
            assert pattern_str not in seen_indicators, f"Duplicate indicator pattern found: {pattern_str}"
            seen_indicators.add(pattern_str)

    print(f"    [PASS] 3. UUIDv4, timestamps, and STIX 2.1 fields validated ({len(indicators)} unique indicators).")

    # [4] Official python-stix2 library full parse
    print("[*] Performing strict deserialization via OASIS python-stix2 library...")
    try:
        stix_bundle_obj = stix2.parse(data, allow_custom=False)
        assert stix_bundle_obj is not None
        assert stix_bundle_obj.type == 'bundle'
    except Exception as e:
        raise AssertionError(f"Official python-stix2 library rejected bundle: {e}")
    print("    [PASS] 4. Official python-stix2 library accepted and validated bundle.")

    print("\n" + "=" * 80)
    print(f"  STIX 2.1 VERIFICATION COMPLETE: ALL {len(data['objects'])} OBJECTS FULLY CONFORMANT!")
    print("=" * 80)

if __name__ == '__main__':
    test_stix_export()
