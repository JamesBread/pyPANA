# run_tests.py Documentation

## Overview
Comprehensive test runner script for the pyPANA project that organizes and executes test suites in logical groups.

## Purpose
This script provides a centralized way to run all pyPANA tests with:
- Organized test grouping by functionality
- Progress tracking and reporting
- Detailed success/failure analysis
- Modular test execution

## Architecture

### Test Discovery
The script uses Python's `importlib` to dynamically load and execute test modules:
```python
spec = importlib.util.spec_from_file_location(module_name, test_file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
```

### Test Execution Strategy
1. Looks for `run_all_tests()` function first
2. Falls back to executing all `test_*` functions
3. Reports if no test functions are found

## Test Groups

### 1. Core Tests
Basic functionality and structure validation:
- `test_basic.py` - Basic pyPANA operations
- `test_pana.py` - PANA protocol implementation
- `test_structure.py` - Code structure validation

### 2. Phase 1 - Security
Security and certificate handling:
- `test_cert_validation.py` - X.509 certificate validation
- `test_phase1_validation.py` - Phase 1 security validation

### 3. Phase 2 - Integration
EAP and protocol integration:
- `test_pana_eap_integration.py` - PANA-EAP integration
- `test_phase2_encapsulation.py` - Message encapsulation
- `test_eap_tls_integration.py` - EAP-TLS integration

### 4. Phase 3 - Enterprise
Advanced enterprise features:
- `test_phase3_enterprise.py` - Enterprise features
- `test_eap_fragmentation.py` - EAP fragmentation handling
- `test_tls_session_cache.py` - TLS session caching

### 5. Key Functionality
Critical functionality tests:
- `test_tls_keyexport.py` - TLS key export (MSK/EMSK)
- `test_revised_comprehensive.py` - Comprehensive test suite

## Usage

### Running All Tests
```bash
python3 run_tests.py
```

### Expected Output Structure
```
======================================================================
  pyPANA TEST SUITE RUNNER
======================================================================

######################################################################
  Core Tests
######################################################################

======================================================================
  Running: tests/test_basic.py
======================================================================
✅ test_basic.py completed successfully

######################################################################
  Phase 1 - Security
######################################################################
[...]

======================================================================
  TEST SUMMARY
======================================================================

Total test files: 13
Passed: 13
Failed: 0

✅ ALL TESTS PASSED!
```

## Test File Requirements

### Method 1: run_all_tests Function
Test files should implement a `run_all_tests()` function:
```python
def run_all_tests():
    """Run all tests in this module"""
    test_function_1()
    test_function_2()
    return True  # or raise exception on failure
```

### Method 2: test_ Prefix Convention
Alternatively, use functions prefixed with `test_`:
```python
def test_feature_one():
    """Test feature one"""
    assert condition, "Test failed"

def test_feature_two():
    """Test feature two"""
    assert condition, "Test failed"
```

## Error Handling

### Individual Test Failures
- Catches exceptions from each test file
- Prints error message and stack trace
- Continues with remaining tests
- Tracks failed tests for summary

### Missing Test Files
```
⚠️ Test file not found: test_example.py
```

### No Test Functions
```
⚠️ No test functions found in test_empty.py
```

## Return Codes
- **0**: All tests passed
- **1**: One or more tests failed

## Customization

### Adding New Test Groups
Edit the `test_groups` dictionary:
```python
test_groups = {
    "New Category": [
        "test_new_feature.py",
        "test_another_feature.py",
    ],
    # ... existing groups
}
```

### Modifying Test Discovery
Change test function pattern in line 65:
```python
if name.startswith('test_'):  # Change pattern here
```

### Adjusting Output Format
Modify separator characters and formatting:
```python
print(f"{'='*70}")  # Change separator style
print(f"{'#'*70}")  # Change group separator
```

## Performance Considerations

### Sequential Execution
Tests run sequentially to avoid:
- Port conflicts
- Resource contention
- Output interleaving

### Module Caching
Each test module is loaded fresh:
- No cross-test contamination
- Clean state for each test

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Run Tests
  run: |
    python3 run_tests.py
  continue-on-error: false
```

### Jenkins Pipeline
```groovy
stage('Test') {
    steps {
        sh 'python3 run_tests.py'
    }
}
```

## Troubleshooting

### Import Errors
```bash
# Ensure PYTHONPATH includes project root
export PYTHONPATH=$PYTHONPATH:.
python3 run_tests.py
```

### Permission Issues
Some tests may require specific permissions:
```bash
# For tests using low port numbers
sudo python3 run_tests.py
```

### Timeout Issues
Individual test files should handle their own timeouts. If a test hangs, it may need internal timeout handling.

## Maintenance

### Updating Test Lists
When adding new tests:
1. Add test file to appropriate group in `test_groups`
2. Ensure test file follows naming convention
3. Implement either `run_all_tests()` or `test_*` functions

### Deprecated Tests
Remove or comment out deprecated tests from `test_groups`:
```python
# "test_old_feature.py",  # Deprecated in v2.3.0
```

## Related Documentation
- `TEST_DOCUMENTATION.md` - Detailed test descriptions
- `TEST_CATEGORIZATION.md` - Test organization and status
- Individual test documentation files (TEST_*.md)