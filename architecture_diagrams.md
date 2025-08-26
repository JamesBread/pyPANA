# pyPANA Architecture Diagrams

This document provides visual representations of the pyPANA implementation architecture using Mermaid diagrams. These diagrams help developers understand the system structure, message flows, and component interactions.

## Table of Contents
- [System Overview](#system-overview)
- [PANA Protocol Message Flow](#pana-protocol-message-flow)
- [Class Architecture](#class-architecture)
- [State Machine Diagrams](#state-machine-diagrams)
- [Component Interaction](#component-interaction)
- [Security Architecture](#security-architecture)
- [EAP-TLS Integration](#eap-tls-integration)

## System Overview

### High-Level Architecture

```mermaid
graph TB
    subgraph "PANA Client (PaC)"
        PC[PANAClient]
        PCE[ClientEncryptionHelper]
        PCC[CryptoContext]
        ETH1[EAPTLSHandler]
    end
    
    subgraph "PANA Auth Agent (PAA)"
        PA[PANAAuthAgent]
        PSE[ServerEncryptionHelper]
        PSC[CryptoContext]
        SM[SessionManager]
        ETH2[EAPTLSHandler]
        RB[RADIUS Backend<br/>Optional]
    end
    
    subgraph "Shared Components"
        PM[PANAMessage]
        AVP[AVP Handler]
        RT[RetransmissionManager]
        AR[AntiReplay]
        STAT[Statistics]
    end
    
    PC <--> PM
    PA <--> PM
    PC --> PCE
    PA --> PSE
    PC --> PCC
    PA --> PSC
    PA --> SM
    PA -.-> RB
    
    PC --> RT
    PA --> RT
    PC --> AR
    PA --> AR
    
    style PC fill:#e1f5fe
    style PA fill:#c8e6c9
    style PM fill:#fff9c4
```

## PANA Protocol Message Flow

### Complete Authentication Flow (RFC 5191 Compliant)

```mermaid
sequenceDiagram
    participant PaC as PANA Client (PaC)
    participant PAA as PANA Auth Agent (PAA)
    participant RADIUS as RADIUS Server<br/>(Optional)
    
    Note over PaC,PAA: Phase 1: Discovery and Initiation
    PaC->>PAA: PCI (flags=0x0000)<br/>Session-ID=0, Seq=0, No AVPs
    
    Note over PaC,PAA: Phase 2: Initial Handshake
    PAA->>PaC: PAR (flags=0xc000, R|S bits)<br/>PRF/Integrity Algorithms
    Note right of PAA: Store as I_PAR
    PaC->>PAA: PAN (flags=0x4000, S bit)<br/>Selected Algorithms
    Note left of PaC: Store as I_PAN
    
    Note over PaC,PAA: Phase 3: Nonce Exchange + EAP
    PAA->>PaC: PAR (flags=0x8000, R bit)<br/>Nonce(PAA), EAP-Request/Identity
    PaC->>PAA: PAN (flags=0x0000)<br/>Nonce(PaC), EAP-Response/Identity
    
    opt RADIUS Backend
        PAA->>RADIUS: Access-Request
        RADIUS->>PAA: Access-Challenge
    end
    
    loop EAP-TLS Handshake
        PAA->>PaC: PAR (flags=0x8000, R bit)<br/>EAP-Request/TLS
        PaC->>PAA: PAN (flags=0x0000)<br/>EAP-Response/TLS
    end
    
    Note over PaC,PAA: Phase 4: Completion
    PAA->>PaC: PAR (flags=0xa000, R|C bits)<br/>EAP-Success, Key-ID, AUTH AVP
    Note right of PAA: MSK → PANA_AUTH_KEY
    PaC->>PAA: PAN (flags=0x2000, C bit)<br/>Key-ID, AUTH AVP
    Note left of PaC: Verify AUTH, derive keys
    
    Note over PaC,PAA: Phase 5: Authenticated State
    PaC-->>PAA: PANA-Notification (Ping)
    PAA-->>PaC: PANA-Notification (Pong)
```

### Re-authentication Flow

```mermaid
sequenceDiagram
    participant PaC as PANA Client
    participant PAA as PANA Auth Agent
    
    Note over PaC,PAA: Session Active (OPEN state)
    
    PAA->>PaC: PNR (A-bit set)<br/>Re-auth Request
    PaC->>PAA: PNA (A-bit set)<br/>Re-auth Response
    
    PAA->>PaC: PAR (EAP-Request/Identity)
    PaC->>PAA: PAN (EAP-Response/Identity)
    
    Note over PaC,PAA: Abbreviated EAP-TLS
    PAA->>PaC: PAR (EAP-Request/TLS)
    PaC->>PAA: PAN (EAP-Response/TLS)
    
    PAA->>PaC: PAR (C-bit, EAP-Success)
    PaC->>PAA: PAN (C-bit)
    
    Note over PaC,PAA: Session Extended
```

## Class Architecture

### Core Classes

```mermaid
classDiagram
    class PANAMessage {
        +reserved: int
        +flags: int
        +msg_type: int
        +session_id: int
        +seq_number: int
        +avps: List[AVP]
        +pack() bytes
        +unpack(data) PANAMessage
        +is_request() bool
        +add_avp(avp)
        +get_avp(code) AVP
    }
    
    class AVP {
        +code: int
        +flags: int
        +value: bytes
        +pack() bytes
        +unpack(data) AVP
    }
    
    class PANAClient {
        +state: int
        +session_id: int
        +seq_number: int
        +crypto_ctx: CryptoContext
        +eap_handler: EAPTLSHandler
        +retransmit_mgr: RetransmissionManager
        +run()
        +handle_auth_msg(msg)
        +send_pci()
        +terminate_session()
    }
    
    class PANAAuthAgent {
        +session_mgr: SessionManager
        +retransmit_mgr: RetransmissionManager
        +radius_client: RadiusClient
        +statistics: PANAStatistics
        +run()
        +handle_pci(msg, addr)
        +handle_auth_msg(msg, addr)
        +send_message(msg, addr)
    }
    
    class CryptoContext {
        +prf_algorithm: int
        +auth_algorithm: int
        +pana_auth_key: bytes
        +pana_pac_encr_key: bytes
        +pana_paa_encr_key: bytes
        +derive_keys(msk, emsk)
        +compute_auth(data) bytes
        +verify_auth(data, auth) bool
    }
    
    class SessionManager {
        +sessions: Dict
        +create_session(key) Session
        +get_session(key) Session
        +remove_session(key)
        +cleanup_expired()
    }
    
    PANAMessage --> AVP : contains
    PANAClient --> PANAMessage : creates/processes
    PANAClient --> CryptoContext : uses
    PANAAuthAgent --> PANAMessage : creates/processes
    PANAAuthAgent --> SessionManager : manages
    SessionManager --> CryptoContext : contains
```

### Security Components

```mermaid
classDiagram
    class EncryptionPolicy {
        +never_encrypt_avps: Set
        +mandatory_encrypt_avps: Set
        +optional_encrypt_avps: Set
        +encryption_enabled: bool
        +validate_encryption_policy(avps, encrypted) tuple
        +should_encrypt_avp(code) bool
    }
    
    class AntiReplay {
        +window_size: int
        +highest_seq: int
        +received_seqs: Set
        +check_and_update(seq_num) bool
        -_slide_window(new_seq)
        -_reset_window(new_seq)
    }
    
    class ServerEncryptionHelper {
        +encryption_policy: EncryptionPolicy
        +process_encrypted_message(msg, session) List[AVP]
        +prepare_message_with_encryption(msg, session)
        +negotiate_encryption(msg, session)
    }
    
    class ClientEncryptionHelper {
        +encryption_context: EncryptionContext
        +handle_server_algorithm(msg)
        +process_encrypted_message(msg, crypto_ctx) List[AVP]
        +prepare_message_with_encryption(msg, crypto_ctx)
    }
    
    class RetransmissionManager {
        +pending_messages: Dict
        +timers: Dict
        +add_message(seq_num, msg_data, addr, callback)
        +remove_message(seq_num)
        +handle_timeout(seq_num)
    }
    
    ServerEncryptionHelper --> EncryptionPolicy : uses
    ClientEncryptionHelper --> EncryptionPolicy : uses
    PANAAuthAgent --> AntiReplay : uses
    PANAClient --> AntiReplay : uses
```

## State Machine Diagrams

### PaC (Client) State Machine

```mermaid
stateDiagram-v2
    [*] --> INITIAL
    INITIAL --> WAIT_PAN_OR_PAR: Send PCI
    
    WAIT_PAN_OR_PAR --> WAIT_EAP_MSG: Receive PAR(S-bit)
    WAIT_EAP_MSG --> WAIT_EAP_MSG: EAP Exchange
    WAIT_EAP_MSG --> WAIT_EAP_RESULT: EAP-TLS Complete
    
    WAIT_EAP_RESULT --> OPEN: Receive PAR(C-bit,Success)
    WAIT_EAP_RESULT --> INITIAL: Receive PAR(C-bit,Failure)
    
    OPEN --> OPEN: Ping/Pong
    OPEN --> OPEN: Re-authentication
    OPEN --> INITIAL: Termination
    
    state OPEN {
        [*] --> Authenticated
        Authenticated --> ReAuth: A-bit PNR
        ReAuth --> Authenticated: Success
    }
```

### PAA (Server) State Machine

```mermaid
stateDiagram-v2
    [*] --> INITIAL
    INITIAL --> WAIT_PAN_OR_PAR: Receive PCI
    
    WAIT_PAN_OR_PAR --> WAIT_EAP_MSG: Receive PAN(S-bit)
    WAIT_EAP_MSG --> WAIT_EAP_MSG: EAP Exchange
    WAIT_EAP_MSG --> WAIT_SUCC_PAN: Send PAR(C-bit,Success)
    WAIT_EAP_MSG --> INITIAL: Authentication Failed
    
    WAIT_SUCC_PAN --> OPEN: Receive PAN(C-bit)
    
    OPEN --> OPEN: Ping/Pong
    OPEN --> OPEN: Re-authentication
    OPEN --> INITIAL: Termination
    
    state OPEN {
        [*] --> SessionActive
        SessionActive --> ReAuthInit: Lifetime < Threshold
        ReAuthInit --> SessionActive: Success
    }
```

## Component Interaction

### Message Processing Flow

```mermaid
flowchart TB
    Start([Receive UDP Packet])
    Parse[Parse PANAMessage]
    Validate{Validate<br/>Message}
    
    CheckReplay{Anti-Replay<br/>Check}
    CheckSession{Session<br/>Exists?}
    
    DecryptAVP{Encrypted<br/>AVPs?}
    Decrypt[Decrypt AVPs]
    ValidatePolicy{Validate<br/>Encryption Policy}
    
    CheckAuth{AUTH AVP<br/>Required?}
    VerifyAuth{Verify<br/>AUTH AVP}
    
    ProcessMsg[Process Message<br/>by Type]
    
    PCI[Handle PCI]
    AUTH[Handle Auth]
    NOTIF[Handle Notification]
    TERM[Handle Termination]
    
    UpdateState[Update State]
    SendResponse[Send Response]
    End([Complete])
    
    Start --> Parse
    Parse --> Validate
    Validate -->|Invalid| End
    Validate -->|Valid| CheckReplay
    
    CheckReplay -->|Fail| End
    CheckReplay -->|Pass| CheckSession
    
    CheckSession -->|No| PCI
    CheckSession -->|Yes| DecryptAVP
    
    DecryptAVP -->|Yes| Decrypt
    DecryptAVP -->|No| CheckAuth
    Decrypt --> ValidatePolicy
    
    ValidatePolicy -->|Fail| End
    ValidatePolicy -->|Pass| CheckAuth
    
    CheckAuth -->|Yes| VerifyAuth
    CheckAuth -->|No| ProcessMsg
    VerifyAuth -->|Fail| End
    VerifyAuth -->|Pass| ProcessMsg
    
    ProcessMsg --> |PCI| PCI
    ProcessMsg --> |PAR/PAN| AUTH
    ProcessMsg --> |PNR/PNA| NOTIF
    ProcessMsg --> |PTR/PTA| TERM
    
    PCI --> UpdateState
    AUTH --> UpdateState
    NOTIF --> UpdateState
    TERM --> UpdateState
    
    UpdateState --> SendResponse
    SendResponse --> End
```

## Security Architecture

### Key Derivation Process

```mermaid
flowchart LR
    subgraph "Input Material"
        MSK[MSK from EAP-TLS<br/>64 bytes]
        IPAR[I_PAR Message]
        IPAN[I_PAN Message]
    end
    
    subgraph "Key Derivation Function"
        PRF[PRF+<br/>HMAC-SHA256]
    end
    
    subgraph "Output Keys"
        AUTH[PANA_AUTH_KEY<br/>32 bytes]
        PACENC[PANA_PAC_ENCR_KEY<br/>16 bytes]
        PAAENC[PANA_PAA_ENCR_KEY<br/>16 bytes]
    end
    
    MSK --> PRF
    IPAR --> PRF
    IPAN --> PRF
    
    PRF --> AUTH
    PRF --> PACENC
    PRF --> PAAENC
    
    style MSK fill:#ffecb3
    style AUTH fill:#c8e6c9
    style PACENC fill:#e1f5fe
    style PAAENC fill:#e1f5fe
```

### Message Authentication

```mermaid
flowchart TB
    subgraph "Message Creation"
        MSG1[Create PANAMessage]
        ADD1[Add AVPs]
        PACK1[Pack Message]
        COMPUTE[Compute AUTH<br/>HMAC-SHA256-128]
        ADD2[Add AUTH AVP]
        PACK2[Final Pack]
    end
    
    subgraph "Message Verification"
        RECV[Receive Message]
        EXTRACT[Extract AUTH AVP]
        REMOVE[Remove AUTH AVP]
        PACK3[Pack without AUTH]
        VERIFY[Verify HMAC]
    end
    
    MSG1 --> ADD1
    ADD1 --> PACK1
    PACK1 --> COMPUTE
    COMPUTE --> ADD2
    ADD2 --> PACK2
    PACK2 --> SEND[Send Message]
    
    RECV --> EXTRACT
    EXTRACT --> REMOVE
    REMOVE --> PACK3
    PACK3 --> VERIFY
    VERIFY --> |Match| ACCEPT[Accept]
    VERIFY --> |No Match| REJECT[Reject]
    
    style COMPUTE fill:#fff3e0
    style VERIFY fill:#fff3e0
```

## EAP-TLS Integration

### EAP-TLS Handler Architecture

```mermaid
classDiagram
    class EAPTLSFactory {
        +create_eap_tls_handler(is_server, cert_file, key_file, ca_cert) EAPTLSHandler
    }
    
    class EAPTLSHandler {
        <<interface>>
        +process_eap_message(data) bytes
        +get_msk() bytes
        +get_emsk() bytes
        +state: str
    }
    
    class EAPTLSPyOpenSSL {
        +ssl_ctx: SSL.Context
        +ssl_conn: SSL.Connection
        +process_eap_message(data) bytes
        +get_msk() bytes
        -_extract_master_secret() bytes
    }
    
    class EAPTLSStandard {
        +ssl_ctx: ssl.SSLContext
        +incoming_bio: ssl.MemoryBIO
        +process_eap_message(data) bytes
        +get_msk() bytes
    }
    
    EAPTLSFactory --> EAPTLSHandler : creates
    EAPTLSPyOpenSSL --|> EAPTLSHandler : implements
    EAPTLSStandard --|> EAPTLSHandler : implements
    
    note for EAPTLSPyOpenSSL "Preferred: Supports proper MSK export"
    note for EAPTLSStandard "Fallback: Limited MSK derivation"
```

### EAP Message Flow

```mermaid
sequenceDiagram
    participant PANA as PANA Layer
    participant EAP as EAP Handler
    participant TLS as TLS Engine
    participant RADIUS as RADIUS<br/>(Optional)
    
    PANA->>EAP: process_eap_message(EAP-Request/Identity)
    EAP->>PANA: EAP-Response/Identity
    
    PANA->>EAP: process_eap_message(EAP-Request/TLS Start)
    EAP->>TLS: Initialize TLS
    TLS->>EAP: ClientHello
    EAP->>PANA: EAP-Response/TLS(ClientHello)
    
    loop TLS Handshake
        PANA->>EAP: EAP-Request/TLS(fragment)
        EAP->>TLS: Process TLS data
        TLS->>EAP: TLS response
        EAP->>PANA: EAP-Response/TLS(fragment)
    end
    
    PANA->>EAP: EAP-Request/TLS(Finished)
    EAP->>TLS: Verify Finished
    TLS->>EAP: Handshake Complete
    EAP->>EAP: Derive MSK/EMSK
    EAP->>PANA: EAP-Response/TLS(Finished)
    
    PANA->>EAP: get_msk()
    EAP->>PANA: MSK (64 bytes)
```

## RADIUS Integration

### RADIUS Backend Flow

```mermaid
flowchart TB
    subgraph "PAA with RADIUS"
        PAA[PANAAuthAgent]
        RH[RADIUS Handler]
        RC[pyrad.Client]
    end
    
    subgraph "RADIUS Server"
        RS[RADIUS Service]
        UDB[(User Database)]
    end
    
    PAC[PANA Client] -->|PAN(EAP-Response)| PAA
    PAA -->|Extract EAP| RH
    RH -->|Create Access-Request| RC
    RC -->|UDP 1812| RS
    RS -->|Validate| UDB
    RS -->|Access-Challenge| RC
    RC -->|Extract EAP| RH
    RH -->|Return EAP| PAA
    PAA -->|PAR(EAP-Request)| PAC
```

## Performance Considerations

### Session Management

```mermaid
flowchart LR
    subgraph "Session Storage"
        HT[Hash Table<br/>O(1) lookup]
        SK[Session Key:<br/>(session_id, client_ip)]
    end
    
    subgraph "Cleanup Strategy"
        TC[Timer-based<br/>Cleanup]
        EC[Event-based<br/>Cleanup]
        MC[Memory<br/>Threshold]
    end
    
    subgraph "Optimization"
        CP[Connection<br/>Pooling]
        CB[Circular<br/>Buffer]
        LRU[LRU Cache<br/>Statistics]
    end
    
    SK --> HT
    HT --> TC
    HT --> EC
    HT --> MC
    
    TC --> CP
    EC --> CB
    MC --> LRU
```

## Summary

The pyPANA architecture follows a modular design with clear separation of concerns:

1. **Protocol Layer**: Handles PANA message format and state machines
2. **Security Layer**: Manages cryptographic operations and key derivation
3. **EAP Layer**: Provides pluggable authentication methods (currently EAP-TLS)
4. **Transport Layer**: UDP socket management with retransmission
5. **Management Layer**: Session lifecycle, statistics, and monitoring

The implementation prioritizes:
- RFC compliance (RFC 5191, RFC 6786, RFC 5216)
- Security (proper key derivation, anti-replay, encryption)
- Extensibility (pluggable EAP methods, RADIUS backend)
- Performance (efficient session management, connection pooling)