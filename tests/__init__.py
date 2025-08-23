"""
pyPANA テストスイート
pyPANA Test Suite

【概要】
pyPANAプロジェクトのすべてのテストファイルが含まれています。
テストは段階的に構成され、基本機能からエンタープライズ機能まで
包括的にカバーしています。

This directory contains all test files for the pyPANA project.

【テスト構成 / Test Organization】
- test_basic.py: 基本機能テスト / Basic functionality tests
- test_pana.py: 主要PANAプロトコルテスト / Core PANA protocol tests
- test_eap_tls_integration.py: EAP-TLS統合テスト / EAP-TLS integration tests
- test_cert_validation.py: 証明書検証テスト（フェーズ1）/ Certificate validation tests (Phase 1)
- test_pana_eap_integration.py: PANA-EAP統合テスト（フェーズ2）/ PANA-EAP integration tests (Phase 2)
- test_phase3_enterprise.py: エンタープライズ機能テスト（フェーズ3）/ Enterprise features tests (Phase 3)
- test_eap_fragmentation.py: EAP断片化テスト / EAP fragmentation tests
- test_tls_session_cache.py: TLSセッションキャッシュテスト / TLS session cache tests
- test_radius_backend.py: RADIUSバックエンドテスト / RADIUS backend tests
- test_openpana_interop.py: OpenPANA相互運用性テスト / OpenPANA interoperability tests

【実行方法 / Usage】
python3 run_tests.py または ./tests/run_final_test.sh を使用してください。
Use python3 run_tests.py or ./tests/run_final_test.sh to run all tests.
"""